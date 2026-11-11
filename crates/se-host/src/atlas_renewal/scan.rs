use super::*;
impl NativeRenewal {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn step(
        &mut self,
        source: &Source,
        connection: &CacheConnection<'_>,
        policy: &AtlasPolicy,
        work: &Scheduled,
        deadline: Instant,
    ) -> AtlasResult<Step> {
        if work.root != source.scope.registration.root {
            return Err(SeError::invalid(
                "renewal work",
                "the bound registered root",
            ));
        }
        let index = self.root(source, connection, policy, deadline)?;
        let serial = i64::try_from(work.serial).map_err(sql_error)?;
        let head_change = matches!(
            work.hint,
            SourceHint::Reconcile(ReconcileReason::GitHeadChanged)
        );
        connection.write(65536, deadline, |sql| {
            batch::begin(
                sql,
                work.serial,
                if head_change {
                    BulkReason::HeadChange
                } else {
                    BulkReason::FilesystemBurst
                },
                head_change,
            )
        })?;
        let reconcile =
            matches!(work.hint, SourceHint::Reconcile(_)) || self.roots[index].requires_reconcile;
        if self.cycle.as_ref().is_none_or(|c| {
            c.root != work.root || c.serial != work.serial || c.reconcile != reconcile
        }) {
            let retained_last = connection.read(deadline, |sql| {
                sql.prepare("SELECT coalesce(max(id),0) FROM files")?
                    .query_row([], |r| r.get::<_, i64>(0))
                    .map_err(sql_error)
            })?;
            connection.write(65536, deadline, |sql| {
                sql.prepare("DELETE FROM renewal_directories")?
                    .execute([])
                    .map_err(sql_error)?;
                if reconcile {
                    sql.prepare("INSERT INTO renewal_directories(path_key,serial) VALUES('',?1)")?
                        .execute([serial])
                        .map_err(sql_error)?;
                }
                Ok(())
            })?;
            if reconcile {
                let root = &mut self.roots[index];
                root.unwatched = 0;
                root.discovery_complete = false;
                root.reasons.clear();
            }
            if reconcile {
                self.refresh_metadata(index, source, deadline)?;
            }
            if reconcile {
                let identity = self.roots[index]
                    .native
                    .as_ref()
                    .ok_or_else(|| source_error("root subscription", "root closed"))?
                    .root
                    .physical_identity()
                    .map_err(|e| source_error("root subscription", e))?;
                self.subscribe(index, connection, "", identity, deadline)?;
            }
            self.cycle = Some(Cycle {
                root: work.root.clone(),
                serial: work.serial,
                reconcile,
                cursor: None,
                rules: None,
                pending_entry: None,
                phase: if reconcile {
                    Phase::Retained
                } else {
                    Phase::Repairs
                },
                after: 0,
                retained_last,
                directories: 1,
                files: 0,
                part: 0,
                coverage: se_atlas::coverage::CoverageScan::default(),
            });
        }
        let mut cycle = self
            .cycle
            .take()
            .ok_or_else(|| SeError::invalid("renewal cursor", "a retained work cycle"))?;
        let work_deadline = deadline
            .checked_sub(Duration::from_millis(25))
            .unwrap_or(deadline);
        let mut completed_files = 0;
        let result = (|| {
            if !reconcile && cycle.part < 2 {
                match &work.hint {
                    SourceHint::FileChanged(path) | SourceHint::FileRemoved(path) => {
                        completed_files += u32::from(observe::eligible_file(
                            source,
                            connection,
                            policy,
                            &self.profiles,
                            path,
                            observe::Mode::Observed(work.serial),
                            work_deadline,
                        )?);
                    }
                    SourceHint::Rename { from, to } => {
                        completed_files += u32::from(observe::eligible_file(
                            source,
                            connection,
                            policy,
                            &self.profiles,
                            if cycle.part == 0 { from } else { to },
                            observe::Mode::Observed(work.serial),
                            work_deadline,
                        )?);
                        cycle.part += 1;
                        if cycle.part < 2 {
                            return Ok(false);
                        }
                    }
                    SourceHint::Reconcile(_) => (),
                }
                cycle.part = 2;
                cycle.phase = Phase::Repairs;
            }
            for _ in 0..8 {
                if work_deadline.saturating_duration_since(Instant::now())
                    < Duration::from_millis(25)
                {
                    break;
                }
                match cycle.phase {
                    Phase::Directories => {
                        if cycle.cursor.is_none() {
                            let path = connection.read(work_deadline, |sql| {
                                let mut statement = sql.prepare(
                                    "SELECT path_key FROM renewal_directories ORDER BY path_key LIMIT 1",
                                )?;
                                let mut rows = statement.query([]).map_err(sql_error)?;
                                rows.next()
                                    .map_err(sql_error)?
                                    .map(|r| r.get::<_, String>(0).map_err(sql_error))
                                    .transpose()
                            })?;
                            let Some(path) = path else {
                                cycle.phase = Phase::Files;
                                cycle.after = 0;
                                continue;
                            };
                            let allowed = if path.is_empty() {
                                true
                            } else {
                                let parent = path.rsplit_once('/').map_or("", |p| p.0);
                                ignore::Rules::load(source, policy, parent, work_deadline)?
                                    .eligible(&path, true, policy, work_deadline)?
                            };
                            let native = self.roots[index]
                                .native
                                .as_ref()
                                .ok_or_else(|| source_error(&path, "root closed"))?;
                            if !allowed {
                                remove_pending(connection, &path, work_deadline)?;
                                continue;
                            }
                            let Some(cursor) = NativeWatchDirectory::open(&native.root, &path)
                                .map_err(|e| source_error(&path, e))?
                            else {
                                remove_pending(connection, &path, work_deadline)?;
                                continue;
                            };
                            if !path.is_empty() {
                                self.subscribe(
                                    index,
                                    connection,
                                    &path,
                                    cursor
                                        .physical_identity()
                                        .map_err(|e| source_error(&path, e))?,
                                    work_deadline,
                                )?;
                            }

                            cycle.cursor = Some(cursor);
                            // This directory's own rule file is descendant
                            // content: read it only after its native subscription.
                            cycle.rules =
                                Some(ignore::Rules::load(source, policy, &path, work_deadline)?);
                        }
                        if cycle.rules.is_none() {
                            let path = cycle
                                .cursor
                                .as_ref()
                                .ok_or_else(|| source_error("enumeration", "cursor absent"))?
                                .path();
                            let rules = ignore::Rules::load(source, policy, path, work_deadline)?;
                            if !path.is_empty()
                                && !rules.eligible(path, true, policy, work_deadline)?
                            {
                                remove_pending(connection, path, work_deadline)?;
                                cycle.cursor = None;
                                continue;
                            }
                            cycle.rules = Some(rules);
                        }
                        let cursor = cycle
                            .cursor
                            .as_mut()
                            .ok_or_else(|| source_error("enumeration", "cursor absent"))?;
                        if cycle.pending_entry.is_none() {
                            cycle.pending_entry = cursor
                                .next_entry()
                                .map_err(|e| source_error(cursor.path(), e))?;
                        }
                        let Some(entry) = &cycle.pending_entry else {
                            remove_pending(connection, cursor.path(), work_deadline)?;
                            cycle.cursor = None;
                            cycle.rules = None;
                            continue;
                        };
                        let Some(name) = entry.name.to_str() else {
                            reason(&mut self.roots[index], CoverageReason::UnsupportedEncoding);
                            cycle.pending_entry = None;
                            continue;
                        };
                        let spelling = if cursor.path().is_empty() {
                            name.into()
                        } else {
                            format!("{}/{name}", cursor.path())
                        };
                        let path = RelativePath::new(spelling)?;
                        let directory = entry.kind == NativeSourceKind::Directory;
                        if !cycle
                            .rules
                            .as_ref()
                            .ok_or_else(|| source_error(path.as_str(), "ignore rules absent"))?
                            .eligible(path.as_str(), directory, policy, work_deadline)?
                        {
                            cycle.pending_entry = None;
                            continue;
                        }
                        match entry.kind {
                            NativeSourceKind::Directory => {
                                if cycle.directories >= policy.max_files {
                                    return Err(limit(
                                        "eligible directories",
                                        cycle.directories as u64 + 1,
                                        policy.max_files as u64,
                                    ));
                                }
                                connection.write(65536,work_deadline,|sql|{sql.prepare("INSERT OR IGNORE INTO renewal_directories(path_key,serial) VALUES(?1,?2)")?.execute((path.as_str(),serial)).map_err(sql_error)?;Ok(())})?;
                                cycle.directories += 1;
                            }
                            NativeSourceKind::File => {
                                if cycle.files >= policy.max_files {
                                    reason(&mut self.roots[index], CoverageReason::FileCountLimit);
                                    return Err(limit(
                                        "eligible files",
                                        cycle.files as u64 + 1,
                                        policy.max_files as u64,
                                    ));
                                }
                                observe::file(
                                    source,
                                    connection,
                                    policy,
                                    &self.profiles,
                                    &path,
                                    observe::Mode::Observed(work.serial),
                                    work_deadline,
                                )?;
                                cycle.files += 1;
                                completed_files += 1;
                            }
                            NativeSourceKind::Link | NativeSourceKind::Other => (),
                        }
                        cycle.pending_entry = None;
                    }
                    Phase::Retained | Phase::Files => {
                        let next = next_path(
                            connection,
                            "SELECT id,path FROM files WHERE id>?1 AND id<=?2 ORDER BY id LIMIT 1",
                            cycle.after,
                            cycle.retained_last,
                            work_deadline,
                        )?;
                        let Some((id, path)) = next else {
                            cycle.phase = if cycle.phase == Phase::Retained {
                                Phase::Directories
                            } else {
                                Phase::Watches
                            };
                            cycle.after = 0;
                            continue;
                        };
                        let path = RelativePath::new(path)?;
                        let parent = path.as_str().rsplit_once('/').map_or("", |p| p.0);
                        let rules = ignore::Rules::load(source, policy, parent, work_deadline)?;
                        if !rules.eligible(path.as_str(), false, policy, work_deadline)? {
                            connection.write(WAL, work_deadline, |sql| {
                                observation::excluded(sql, &source.scope, &path, work.serial)
                                    .map(|_| ())
                            })?;
                        } else {
                            match source.open(&path) {
                                Ok(None) => connection.write(WAL, work_deadline, |sql| {
                                    observation::removed(
                                        sql,
                                        &source.scope,
                                        &path,
                                        false,
                                        work.serial,
                                    )
                                    .map(|_| ())
                                })?,
                                Err(error) => connection.write(WAL, work_deadline, |sql| {
                                    observation::unparsed(
                                        sql,
                                        &source.scope,
                                        &path,
                                        se_atlas::policy::language(&path),
                                        observation::UnparsedObservation::Failed(&error.body),
                                        work.serial,
                                    )
                                    .map(|_| ())
                                })?,
                                Ok(Some(_)) => (),
                            }
                        }
                        cycle.after = id;
                    }
                    Phase::Watches => {
                        let next = next_path(
                            connection,
                            "SELECT id,path FROM watch_directories WHERE id>?1 AND id<=?2 ORDER BY id LIMIT 1",
                            cycle.after,
                            i64::MAX,
                            work_deadline,
                        )?;
                        let Some((id, path)) = next else {
                            cycle.phase = Phase::Repairs;
                            self.roots[index].discovery_complete = true;
                            continue;
                        };
                        let rules = ignore::Rules::load(source, policy, &path, work_deadline)?;
                        let native = self.roots[index]
                            .native
                            .as_ref()
                            .ok_or_else(|| source_error(&path, "root closed"))?;
                        if (!path.is_empty()
                            && !rules.eligible(&path, true, policy, work_deadline)?)
                            || native
                                .root
                                .open_directory(&path)
                                .map_err(|e| source_error(&path, e))?
                                .is_none()
                        {
                            if let Some(mapping) = self
                                .mappings
                                .iter()
                                .find(|m| m.root == index as u32 && m.directory == id)
                                .copied()
                            {
                                native
                                    .watch
                                    .remove(mapping.descriptor)
                                    .map_err(|e| source_error(&path, e))?;
                                self.mappings
                                    .retain(|m| m.root != mapping.root || m.directory != id);
                            }
                            connection.write(65536, work_deadline, |sql| {
                                sql.prepare("DELETE FROM watch_directories WHERE id=?1")?
                                    .execute([id])
                                    .map_err(sql_error)?;
                                Ok(())
                            })?;
                        }
                        cycle.after = id;
                    }
                    Phase::Repairs => {
                        let next=connection.read(work_deadline,|sql| {
                            let mut statement=sql.prepare("SELECT path_key,serial FROM pending_paths ORDER BY path_key LIMIT 1")?;
                            let mut rows=statement.query([]).map_err(sql_error)?;
                            rows.next().map_err(sql_error)?.map(|r|Ok((r.get::<_,String>(0).map_err(sql_error)?,r.get::<_,i64>(1).map_err(sql_error)?))).transpose()
                        })?;
                        let Some((path, queued_serial)) = next else {
                            cycle.phase = Phase::Coverage;
                            continue;
                        };
                        let path = RelativePath::new(path)?;
                        completed_files += u32::from(observe::eligible_file(
                            source,
                            connection,
                            policy,
                            &self.profiles,
                            &path,
                            observe::Mode::Repair(work.serial),
                            work_deadline,
                        )?);
                        connection.write(65536, work_deadline, |sql| {
                            sql.prepare(
                                "DELETE FROM pending_paths WHERE path_key=?1 AND serial<=?2",
                            )?
                            .execute((path.as_str(), queued_serial))
                            .map_err(sql_error)?;
                            Ok(())
                        })?;
                    }
                    Phase::Coverage => {
                        // This cycle remains the serialized graph writer. A new
                        // source serial discards it before any further mutation.
                        if cycle.coverage.step(connection, work_deadline)? {
                            cycle.phase = Phase::Done;
                        }
                    }
                    Phase::Done => return Ok(true),
                }
            }
            Ok(false)
        })();
        let complete = match result {
            Ok(complete) => complete,
            Err(error) => {
                self.cycle = Some(cycle);
                return Err(error);
            }
        };
        let summary = summary::get(
            connection,
            &self.roots[index],
            self.mappings
                .iter()
                .filter(|m| m.root == index as u32)
                .count()
                + self.roots[index]
                    .native
                    .as_ref()
                    .and_then(|n| n.metadata.as_ref())
                    .map_or(0, metadata::Watches::len),
            if complete {
                Some(&cycle.coverage)
            } else {
                None
            },
            deadline,
        );
        let summary = match summary {
            Ok(summary) => summary,
            Err(error) => {
                self.cycle = Some(cycle);
                return Err(error);
            }
        };
        if complete && reconcile {
            self.roots[index].requires_reconcile = false;
        }
        let report = WorkReport {
            root: work.root.clone(),
            phase: if reconcile {
                WorkPhase::Discover
            } else {
                WorkPhase::Commit
            },
            completed_files,
            remaining_known: if complete { 0 } else { 1 },
            generation: summary.generation,
            state: summary.state.clone(),
        };
        if !complete {
            self.cycle = Some(cycle);
        }
        Ok(Step {
            report,
            summary,
            complete,
        })
    }
}
fn remove_pending(
    connection: &CacheConnection<'_>,
    path: &str,
    deadline: Instant,
) -> AtlasResult<()> {
    connection.write(65536, deadline, |sql| {
        sql.prepare("DELETE FROM renewal_directories WHERE path_key=?1")?
            .execute([path])
            .map_err(sql_error)?;
        Ok(())
    })
}
fn next_path(
    connection: &CacheConnection<'_>,
    query: &str,
    after: i64,
    last: i64,
    deadline: Instant,
) -> AtlasResult<Option<(i64, String)>> {
    connection.read(deadline, |sql| {
        let mut statement = sql.prepare(query)?;
        let mut rows = statement.query((after, last)).map_err(sql_error)?;
        rows.next()
            .map_err(sql_error)?
            .map(|row| {
                Ok((
                    row.get(0).map_err(sql_error)?,
                    row.get(1).map_err(sql_error)?,
                ))
            })
            .transpose()
    })
}
