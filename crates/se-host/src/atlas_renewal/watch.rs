use super::*;
impl NativeRenewal {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) fn subscribe(
        &mut self,
        index: usize,
        connection: &CacheConnection<'_>,
        path: &str,
        identity: [u8; 32],
        deadline: Instant,
    ) -> AtlasResult<()> {
        let existing = connection.read(deadline, |sql| {
            let mut statement =
                sql.prepare("SELECT descriptor,identity FROM watch_directories WHERE path=?1")?;
            let mut rows = statement.query([path]).map_err(sql_error)?;
            rows.next()
                .map_err(sql_error)?
                .map(|r| {
                    Ok((
                        r.get::<_, u32>(0).map_err(sql_error)?,
                        r.get::<_, Vec<u8>>(1).map_err(sql_error)?,
                    ))
                })
                .transpose()
        })?;
        if let Some((descriptor, stored)) = existing {
            if stored == identity {
                return Ok(());
            }
            let native = self.roots[index]
                .native
                .as_ref()
                .ok_or_else(|| source_error(path, "closed watch"))?;
            native
                .watch
                .remove(descriptor)
                .map_err(|e| source_error(path, e))?;
            self.mappings
                .retain(|m| m.root != index as u32 || m.descriptor != descriptor);
            connection.write(65536, deadline, |sql| {
                sql.prepare("DELETE FROM watch_directories WHERE descriptor=?1")?
                    .execute([descriptor])
                    .map_err(sql_error)?;
                Ok(())
            })?;
        }
        let metadata_watches: usize = self
            .roots
            .iter()
            .filter_map(|r| r.native.as_ref())
            .filter_map(|r| r.metadata.as_ref())
            .map(metadata::Watches::len)
            .sum();
        if self.mappings.len() + metadata_watches >= self.roots[index].cap as usize {
            let root = &mut self.roots[index];
            if !root.limited_this_activation {
                root.limited_this_activation = true;
                root.limited = root.limited.saturating_add(1);
            }
            root.unwatched = root.unwatched.saturating_add(1);
            reason(root, CoverageReason::PartialWatch);
            return Ok(());
        }
        let native = self.roots[index]
            .native
            .as_ref()
            .ok_or_else(|| source_error(path, "watch closed"))?;
        let registration = match native.watch.subscribe(&native.root, path) {
            Ok(Some(registration)) => registration,
            Ok(None) => return Ok(()),
            Err(error) => {
                let root = &mut self.roots[index];
                if !root.limited_this_activation {
                    root.limited_this_activation = true;
                    root.limited = root.limited.saturating_add(1);
                }
                root.unwatched = root.unwatched.saturating_add(1);
                reason(root, CoverageReason::PartialWatch);
                root.limit_error = Some(error.to_string());
                return Ok(());
            }
        };
        let saved = connection.write(65536, deadline, |sql| {
            sql.prepare(
                "INSERT INTO watch_directories(descriptor,path,identity) VALUES(?1,?2,?3)",
            )?
            .execute((
                registration.descriptor,
                path,
                registration.physical_directory.as_slice(),
            ))
            .map_err(sql_error)?;
            sql.prepare("SELECT id FROM watch_directories WHERE descriptor=?1")?
                .query_row([registration.descriptor], |r| r.get::<_, i64>(0))
                .map_err(sql_error)
        });
        let id = match saved {
            Ok(id) => id,
            Err(original) => {
                native
                    .watch
                    .remove(registration.descriptor)
                    .map_err(|e| source_error(path, e))?;
                return Err(original);
            }
        };
        self.mappings.reserve_exact(1);
        self.mappings.push(Mapping {
            descriptor: registration.descriptor,
            root: index as u32,
            directory: id,
        });
        Ok(())
    }
    pub(super) fn refresh_metadata(
        &mut self,
        index: usize,
        source: &Source,
        deadline: Instant,
    ) -> AtlasResult<()> {
        let used = self.mappings.len()
            + self
                .roots
                .iter()
                .enumerate()
                .filter(|(n, _)| *n != index)
                .filter_map(|(_, r)| r.native.as_ref())
                .filter_map(|n| n.metadata.as_ref())
                .map(metadata::Watches::len)
                .sum::<usize>();
        let root = &mut self.roots[index];
        let native = root
            .native
            .as_mut()
            .ok_or_else(|| source_error("metadata watches", "root closed"))?;
        if let Some(old) = native.metadata.take() {
            old.remove(&native.watch)?;
        }
        if let Some(registration) = &source.scope.registration.git_metadata {
            let watches = metadata::Watches::install(
                registration,
                &native.watch,
                (root.cap as usize).saturating_sub(used),
                deadline,
            )?;
            let held = match watches.lock_held() {
                Ok(held) => held,
                Err(error) => {
                    watches.remove(&native.watch)?;
                    return Err(error);
                }
            };
            observe_lock(root, held);
            if !watches.complete {
                root.unwatched = root.unwatched.saturating_add(watches.unwatched);
                root.limit_error.clone_from(&watches.diagnostic);
                if !root.limited_this_activation {
                    root.limited_this_activation = true;
                    root.limited = root.limited.saturating_add(1);
                }
                reason(root, CoverageReason::PartialWatch);
            }
            root.native
                .as_mut()
                .ok_or_else(|| source_error("metadata watches", "root closed"))?
                .metadata = Some(watches);
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn poll_events(
        &mut self,
        source: &Source,
        connection: &CacheConnection<'_>,
        policy: &AtlasPolicy,
        deadline: Instant,
    ) -> AtlasResult<Vec<SourceHint>> {
        let index = self.root(source, connection, policy, deadline)?;
        // A paused directory cursor needs no second retained rule set while
        // event filtering reads another directory's policy. Reload after readiness.
        if let Some(cycle) = self.cycle.as_mut() {
            cycle.rules = None;
        }
        let mut buffer = [0u8; 16384];
        let native = self.roots[index]
            .native
            .as_ref()
            .ok_or_else(|| source_error("watch", "closed"))?;
        let count = native
            .watch
            .read(&mut buffer)
            .map_err(|e| source_error("watch event read", e))?;
        if let Some(metadata) = native.metadata.as_ref() {
            let held = metadata.lock_held()?;
            observe_lock(&mut self.roots[index], held);
        }
        let mut hints = Vec::new();
        for event in NativeWatchEvents::new(&buffer[..count]) {
            // A bounded reconcile replaces the consumed tail, never silent loss.
            if Instant::now() >= deadline || hints.len() >= 4 {
                reason(&mut self.roots[index], CoverageReason::WatchLoss);
                return Ok(vec![SourceHint::Reconcile(ReconcileReason::WatchOverflow)]);
            }
            let event = match event {
                Ok(event) => event,
                Err(error) => {
                    self.roots[index].limit_error = Some(error.to_string());
                    reason(&mut self.roots[index], CoverageReason::WatchLoss);
                    return Ok(vec![SourceHint::Reconcile(ReconcileReason::WatchFailure)]);
                }
            };
            if event.action == NativeWatchAction::Overflow {
                reason(&mut self.roots[index], CoverageReason::WatchLoss);
                return Ok(vec![SourceHint::Reconcile(ReconcileReason::WatchOverflow)]);
            }
            if let Some(metadata) = self.roots[index]
                .native
                .as_ref()
                .and_then(|n| n.metadata.as_ref())
                && metadata.handles(event.descriptor)
            {
                if let Some(hint) = metadata.hint(&event)? {
                    return Ok(vec![hint]);
                }
                continue;
            }
            let Some(mapping) = self
                .mappings
                .iter()
                .find(|m| m.root == index as u32 && Some(m.descriptor) == event.descriptor)
                .copied()
            else {
                if event.watch_removed {
                    continue;
                }
                reason(&mut self.roots[index], CoverageReason::WatchLoss);
                return Ok(vec![SourceHint::Reconcile(ReconcileReason::WatchFailure)]);
            };
            let directory = connection.read(deadline, |sql| {
                sql.prepare("SELECT path FROM watch_directories WHERE id=?1 AND descriptor=?2")?
                    .query_row((mapping.directory, mapping.descriptor), |r| {
                        r.get::<_, String>(0)
                    })
                    .map_err(sql_error)
            });
            let directory = match directory {
                Ok(path) => path,
                Err(error) => {
                    reason(&mut self.roots[index], CoverageReason::WatchLoss);
                    return Err(error);
                }
            };
            if event.action == NativeWatchAction::Invalidated {
                self.mappings
                    .retain(|m| m.root != mapping.root || m.directory != mapping.directory);
                connection.write(65536, deadline, |sql| {
                    sql.prepare("DELETE FROM watch_directories WHERE id=?1")?
                        .execute([mapping.directory])
                        .map_err(sql_error)?;
                    Ok(())
                })?;
                reason(&mut self.roots[index], CoverageReason::WatchLoss);
                return Ok(vec![SourceHint::Reconcile(
                    ReconcileReason::DirectoryChanged,
                )]);
            }
            let Some(name) = event.name.to_str() else {
                reason(&mut self.roots[index], CoverageReason::UnsupportedEncoding);
                continue;
            };
            if name.is_empty() {
                return Ok(vec![SourceHint::Reconcile(
                    ReconcileReason::DirectoryChanged,
                )]);
            }
            let length = directory.len() + usize::from(!directory.is_empty()) + name.len();
            if length > 4096 {
                return Err(limit("native event path", length as u64, 4096));
            }
            let mut spelling = String::with_capacity(length);
            if !directory.is_empty() {
                spelling.push_str(&directory);
                spelling.push('/');
            }
            spelling.push_str(name);
            let path = RelativePath::new(spelling)?;
            // Rule inputs are always observed. Other ignored churn never enters
            // the shared scheduler, including excluded newly-created trees.
            if name == ".gitignore" {
                return Ok(vec![SourceHint::Reconcile(
                    ReconcileReason::IgnoreRulesChanged,
                )]);
            }
            let rules = ignore::Rules::load(source, policy, &directory, deadline)?;
            if !rules.eligible(path.as_str(), event.directory, policy, deadline)? {
                continue;
            }
            if event.directory {
                return Ok(vec![SourceHint::Reconcile(
                    ReconcileReason::DirectoryChanged,
                )]);
            }
            hints.push(
                if matches!(
                    event.action,
                    NativeWatchAction::Removed | NativeWatchAction::MovedFrom
                ) {
                    SourceHint::FileRemoved(path)
                } else {
                    SourceHint::FileChanged(path)
                },
            );
        }
        Ok(hints)
    }
}

fn observe_lock(root: &mut Root, held: bool) {
    if root.last_lock.is_some_and(|previous| previous != held) || root.last_lock.is_none() && held {
        root.pending_lock = Some(held);
    }
    root.last_lock = Some(held);
}
