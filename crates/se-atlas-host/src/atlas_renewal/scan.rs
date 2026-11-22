use super::*;
struct CycleOutcome {
    complete: bool,
    completed_files: u32,
}

impl NativeRenewal {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn step(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
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
        let full_reconcile =
            matches!(work.hint, SourceHint::Reconcile(_)) || self.roots[index].requires_reconcile;
        let subtree = match &work.hint {
            SourceHint::DirectoryChanged(path) if !full_reconcile => Some(path.clone()),
            _ => None,
        };
        let reconcile = full_reconcile || subtree.is_some();
        if self.cycle.as_ref().is_none_or(|c| {
            c.root != work.root
                || c.serial != work.serial
                || c.reconcile != reconcile
                || c.subtree != subtree
        }) {
            self.begin_cycle(source, connection, index, work, deadline, subtree)?;
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
                let (delta, stop) =
                    self.apply_hint(source, connection, policy, work, &mut cycle, work_deadline)?;
                completed_files += delta;
                if stop {
                    return Ok(false);
                }
            }
            for _ in 0..8 {
                if work_deadline.saturating_duration_since(se_atlas::clock::now())
                    < Duration::from_millis(25)
                {
                    break;
                }
                match cycle.phase {
                    Phase::Directories => {
                        completed_files += self.step_directories(
                            &SourcePolicy { source, policy },
                            connection,
                            index,
                            work,
                            &mut cycle,
                            work_deadline,
                        )?;
                    }
                    Phase::Retained | Phase::Files => {
                        files_repair_step(
                            source,
                            connection,
                            policy,
                            work,
                            &mut cycle,
                            work_deadline,
                        )?;
                    }
                    Phase::Watches => self.step_watches(
                        source,
                        connection,
                        policy,
                        index,
                        &mut cycle,
                        work_deadline,
                    )?,
                    Phase::Repairs => {
                        completed_files += self.step_repairs(
                            source,
                            connection,
                            policy,
                            work,
                            &mut cycle,
                            work_deadline,
                        )?;
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
        self.finish_step(
            connection,
            index,
            work,
            cycle,
            CycleOutcome {
                complete,
                completed_files,
            },
            deadline,
        )
    }
    fn begin_cycle(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
        index: usize,
        work: &Scheduled,
        deadline: Instant,
        subtree: Option<RelativePath>,
    ) -> AtlasResult<()> {
        let full_reconcile =
            matches!(work.hint, SourceHint::Reconcile(_)) || self.roots[index].requires_reconcile;
        let reconcile = full_reconcile || subtree.is_some();
        let serial = i64::try_from(work.serial).map_err(sql_error)?;
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
                sql.prepare("INSERT INTO renewal_directories(path_key,serial) VALUES(?1,?2)")?
                    .execute((subtree.as_ref().map_or("", |path| path.as_str()), serial))
                    .map_err(sql_error)?;
            }
            Ok(())
        })?;
        if full_reconcile {
            let root = &mut self.roots[index];
            root.unwatched = 0;
            root.discovery_complete = false;
            root.reasons.clear();
        }
        if full_reconcile {
            self.refresh_metadata(index, source, deadline)?;
        }
        if full_reconcile {
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
            subtree,
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
        Ok(())
    }

    fn apply_hint(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
        policy: &AtlasPolicy,
        work: &Scheduled,
        cycle: &mut Cycle,
        work_deadline: Instant,
    ) -> AtlasResult<(u32, bool)> {
        let mut completed = 0;
        match &work.hint {
            SourceHint::FileChanged(path) | SourceHint::FileRemoved(path) => {
                completed += u32::from(observe::eligible_file(
                    source,
                    connection,
                    policy,
                    &mut self.parser,
                    path,
                    observe::Mode::Observed(work.serial),
                    work_deadline,
                )?);
            }
            SourceHint::Rename { from, to } => {
                completed += u32::from(observe::eligible_file(
                    source,
                    connection,
                    policy,
                    &mut self.parser,
                    if cycle.part == 0 { from } else { to },
                    observe::Mode::Observed(work.serial),
                    work_deadline,
                )?);
                cycle.part += 1;
                if cycle.part < 2 {
                    return Ok((completed, true));
                }
            }
            SourceHint::DirectoryChanged(_)
            | SourceHint::Reconcile(_)
            | SourceHint::ColdSnapshot => (),
        }
        cycle.part = 2;
        cycle.phase = Phase::Repairs;
        Ok((completed, false))
    }

    fn step_directories(
        &mut self,
        scan: &SourcePolicy<'_>,
        connection: &mut CacheConnection<'_>,
        index: usize,
        work: &Scheduled,
        cycle: &mut Cycle,
        work_deadline: Instant,
    ) -> AtlasResult<u32> {
        let serial = i64::try_from(work.serial).map_err(sql_error)?;
        let mut completed = 0;
        if cycle.cursor.is_none() {
            self.open_directory_cursor(scan, connection, index, cycle, work_deadline)?;
        }
        if cycle.rules.is_none() {
            let path = cycle
                .cursor
                .as_ref()
                .ok_or_else(|| source_error("enumeration", "cursor absent"))?
                .path();
            let rules = ignore::Rules::load(scan.source, &scan.policy.ignore, path, work_deadline)?;
            if !path.is_empty()
                && !rules.eligible(path, true, &scan.policy.ignore, work_deadline)?
            {
                remove_pending(connection, path, work_deadline)?;
                cycle.cursor = None;
                return Ok(completed);
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
            return Ok(completed);
        };
        let Some(path) = self.resolve_entry_path(index, entry, cursor)? else {
            cycle.pending_entry = None;
            return Ok(completed);
        };
        let directory = entry.kind == NativeSourceKind::Directory;
        if !cycle
            .rules
            .as_ref()
            .ok_or_else(|| source_error(path.as_str(), "ignore rules absent"))?
            .eligible(path.as_str(), directory, &scan.policy.ignore, work_deadline)?
        {
            cycle.pending_entry = None;
            return Ok(completed);
        }
        match entry.kind {
            NativeSourceKind::Directory => {
                if cycle.directories >= scan.policy.max_files {
                    return Err(limit(
                        "eligible directories",
                        cycle.directories as u64 + 1,
                        scan.policy.max_files as u64,
                    ));
                }
                connection.write(65536, work_deadline, |sql| {
                    sql.prepare(
                        "INSERT OR IGNORE INTO renewal_directories(path_key,serial) VALUES(?1,?2)",
                    )?
                    .execute((path.as_str(), serial))
                    .map_err(sql_error)?;
                    Ok(())
                })?;
                cycle.directories += 1;
            }
            NativeSourceKind::File => {
                if cycle.files >= scan.policy.max_files {
                    reason(&mut self.roots[index], CoverageReason::FileCountLimit);
                    return Err(limit(
                        "eligible files",
                        cycle.files as u64 + 1,
                        scan.policy.max_files as u64,
                    ));
                }
                observe::file(
                    scan.source,
                    connection,
                    scan.policy,
                    &mut self.parser,
                    &path,
                    observe::Mode::Observed(work.serial),
                    work_deadline,
                )?;
                cycle.files += 1;
                completed += 1;
            }
            NativeSourceKind::Link | NativeSourceKind::Other => (),
        }
        cycle.pending_entry = None;
        Ok(completed)
    }

    fn resolve_entry_path(
        &mut self,
        index: usize,
        entry: &se_proc::NativeSourceEntry,
        cursor: &NativeWatchDirectory,
    ) -> AtlasResult<Option<RelativePath>> {
        let Some(name) = entry.name.to_str() else {
            reason(&mut self.roots[index], CoverageReason::UnsupportedEncoding);
            return Ok(None);
        };
        let spelling = if cursor.path().is_empty() {
            name.into()
        } else {
            format!("{}/{name}", cursor.path())
        };
        Ok(entry_path(&mut self.roots[index], spelling))
    }

    fn open_directory_cursor(
        &mut self,
        scan: &SourcePolicy<'_>,
        connection: &mut CacheConnection<'_>,
        index: usize,
        cycle: &mut Cycle,
        work_deadline: Instant,
    ) -> AtlasResult<()> {
        let path = connection.read(work_deadline, |sql| {
            let mut statement =
                sql.prepare("SELECT path_key FROM renewal_directories ORDER BY path_key LIMIT 1")?;
            let mut rows = statement.query([]).map_err(sql_error)?;
            rows.next()
                .map_err(sql_error)?
                .map(|r| r.get::<_, String>(0).map_err(sql_error))
                .transpose()
        })?;
        let Some(path) = path else {
            cycle.phase = Phase::Files;
            cycle.after = 0;
            return Ok(());
        };
        let allowed =
            if path.is_empty() {
                true
            } else {
                let parent = path.rsplit_once('/').map_or("", |p| p.0);
                ignore::Rules::load(scan.source, &scan.policy.ignore, parent, work_deadline)?
                    .eligible(&path, true, &scan.policy.ignore, work_deadline)?
            };
        let native = self.roots[index]
            .native
            .as_ref()
            .ok_or_else(|| source_error(&path, "root closed"))?;
        if !allowed {
            remove_pending(connection, &path, work_deadline)?;
            return Ok(());
        }
        let opened = NativeWatchDirectory::open(&native.root, &path);
        #[cfg(windows)]
        let opened = match opened {
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => Ok(None),
            result => result,
        };
        let Some(cursor) = opened.map_err(|e| source_error(&path, e))? else {
            remove_pending(connection, &path, work_deadline)?;
            return Ok(());
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
        cycle.rules = Some(ignore::Rules::load(
            scan.source,
            &scan.policy.ignore,
            &path,
            work_deadline,
        )?);
        Ok(())
    }

    fn step_watches(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
        policy: &AtlasPolicy,
        index: usize,
        cycle: &mut Cycle,
        work_deadline: Instant,
    ) -> AtlasResult<()> {
        let next = next_path(
            connection,
            "SELECT id,path FROM watch_directories WHERE id>?1 AND id<=?2 AND atlas_scope(path,NULL,?3,x'') ORDER BY id LIMIT 1",
            cycle.after,
            i64::MAX,
            cycle.subtree.as_ref(),
            work_deadline,
        )?;
        let Some((id, path)) = next else {
            cycle.phase = Phase::Repairs;
            self.roots[index].discovery_complete = true;
            return Ok(());
        };
        let rules = ignore::Rules::load(source, &policy.ignore, &path, work_deadline)?;
        let native = self.roots[index]
            .native
            .as_ref()
            .ok_or_else(|| source_error(&path, "root closed"))?;
        if (!path.is_empty() && !rules.eligible(&path, true, &policy.ignore, work_deadline)?)
            || !directory_present(&native.root, &path)?
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
        Ok(())
    }

    fn step_repairs(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
        policy: &AtlasPolicy,
        work: &Scheduled,
        cycle: &mut Cycle,
        work_deadline: Instant,
    ) -> AtlasResult<u32> {
        let next = connection.read(work_deadline, |sql| {
            let mut statement =
                sql.prepare("SELECT path_key,serial FROM pending_paths ORDER BY path_key LIMIT 1")?;
            let mut rows = statement.query([]).map_err(sql_error)?;
            rows.next()
                .map_err(sql_error)?
                .map(|r| {
                    Ok((
                        r.get::<_, String>(0).map_err(sql_error)?,
                        r.get::<_, i64>(1).map_err(sql_error)?,
                    ))
                })
                .transpose()
        })?;
        let Some((path, queued_serial)) = next else {
            cycle.phase = Phase::Coverage;
            return Ok(0);
        };
        let path = RelativePath::new(path)?;
        let completed = u32::from(observe::eligible_file(
            source,
            connection,
            policy,
            &mut self.parser,
            &path,
            observe::Mode::Repair(work.serial),
            work_deadline,
        )?);
        connection.write(65536, work_deadline, |sql| {
            sql.prepare("DELETE FROM pending_paths WHERE path_key=?1 AND serial<=?2")?
                .execute((path.as_str(), queued_serial))
                .map_err(sql_error)?;
            Ok(())
        })?;
        Ok(completed)
    }

    fn finish_step(
        &mut self,
        connection: &mut CacheConnection<'_>,
        index: usize,
        work: &Scheduled,
        cycle: Cycle,
        outcome: CycleOutcome,
        deadline: Instant,
    ) -> AtlasResult<Step> {
        let full_reconcile =
            matches!(work.hint, SourceHint::Reconcile(_)) || self.roots[index].requires_reconcile;
        let reconcile = full_reconcile || cycle.subtree.is_some();
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
            if outcome.complete {
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
        if outcome.complete && full_reconcile {
            self.roots[index].requires_reconcile = false;
        }
        let report = WorkReport {
            root: work.root.clone(),
            phase: if reconcile {
                WorkPhase::Discover
            } else {
                WorkPhase::Commit
            },
            completed_files: outcome.completed_files,
            remaining_known: if outcome.complete { 0 } else { 1 },
            generation: summary.generation,
            state: summary.state.clone(),
        };
        if !outcome.complete {
            self.cycle = Some(cycle);
        }
        Ok(Step {
            report,
            summary,
            complete: outcome.complete,
        })
    }
}
fn entry_path(root: &mut Root, spelling: String) -> Option<RelativePath> {
    let path_reason = if spelling.len() > 4096 {
        CoverageReason::ByteLimit
    } else {
        CoverageReason::ReadFailure
    };
    RelativePath::new(spelling)
        .map_err(|_| reason(root, path_reason))
        .ok()
}
fn remove_pending(
    connection: &mut CacheConnection<'_>,
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
    connection: &mut CacheConnection<'_>,
    query: &str,
    after: i64,
    last: i64,
    subtree: Option<&RelativePath>,
    deadline: Instant,
) -> AtlasResult<Option<(i64, String)>> {
    connection.read(deadline, |sql| {
        let mut statement = sql.prepare(query)?;
        let scope = subtree.map_or(&[][..], |path| path.as_str().as_bytes());
        let mut rows = statement.query((after, last, scope)).map_err(sql_error)?;
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

fn directory_present(root: &NativeSourceRoot, path: &str) -> AtlasResult<bool> {
    match root.open_directory(path) {
        Ok(directory) => Ok(directory.is_some()),
        #[cfg(windows)]
        Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => Ok(false),
        Err(error) => Err(source_error(path, error)),
    }
}
fn files_repair_step(
    source: &Source,
    connection: &mut CacheConnection<'_>,
    policy: &AtlasPolicy,
    work: &Scheduled,
    cycle: &mut Cycle,
    work_deadline: Instant,
) -> AtlasResult<()> {
    let next = next_path(
        connection,
        "SELECT id,path FROM files WHERE id>?1 AND id<=?2 AND atlas_scope(path,NULL,?3,x'') ORDER BY id LIMIT 1",
        cycle.after,
        cycle.retained_last,
        cycle.subtree.as_ref(),
        work_deadline,
    )?;
    let Some((id, path)) = next else {
        cycle.phase = if cycle.phase == Phase::Retained {
            Phase::Directories
        } else {
            Phase::Watches
        };
        cycle.after = 0;
        return Ok(());
    };
    let path = RelativePath::new(path)?;
    let parent = path.as_str().rsplit_once('/').map_or("", |p| p.0);
    let rules = ignore::Rules::load(source, &policy.ignore, parent, work_deadline)?;
    if !rules.eligible(path.as_str(), false, &policy.ignore, work_deadline)? {
        connection.write(WAL, work_deadline, |sql| {
            observation::excluded(sql, &source.scope, &path, work.serial).map(|_| ())
        })?;
    } else {
        match source.open(&path) {
            Ok(None) => connection.write(WAL, work_deadline, |sql| {
                observation::removed(sql, &source.scope, &path, false, work.serial).map(|_| ())
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
    Ok(())
}
