use super::*;
impl crate::atlas_runtime::RenewalDriver for NativeRenewal {
    fn bind_parser_image(&mut self, image: &std::path::Path) -> AtlasResult<()> {
        self.parser.bind_image(image);
        Ok(())
    }
    fn step(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
        policy: &AtlasPolicy,
        work: &Scheduled,
        deadline: Instant,
    ) -> AtlasResult<Step> {
        NativeRenewal::step(self, source, connection, policy, work, deadline)
    }
    fn poll_events(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
        policy: &AtlasPolicy,
        deadline: Instant,
    ) -> AtlasResult<Vec<SourceHint>> {
        NativeRenewal::poll_events(self, source, connection, policy, deadline)
    }
    fn close(
        &mut self,
        root: &RootId,
        connection: Option<&mut CacheConnection<'_>>,
        deadline: Instant,
    ) -> AtlasResult<()> {
        NativeRenewal::close(self, root, connection, deadline)
    }
    #[cfg(target_os = "linux")]
    fn event_fd(&self, root: &RootId) -> Option<BorrowedFd<'_>> {
        NativeRenewal::event_fd(self, root)
    }
}

/// Native readiness entry point. A failed lookup/read replaces its consumed
/// event bytes with scheduler-owned reconciliation before returning the error.
pub fn drive_events(
    controller: &mut crate::atlas_runtime::NativeController<NativeRenewal>,
    root: &RootId,
    deadline: Instant,
) -> AtlasResult<usize> {
    let hints = match controller.runtime_mut().poll_events(root, deadline) {
        Ok(hints) => hints,
        Err(error) => {
            let driver = controller.runtime_mut().driver_mut();
            eprintln!(
                "ATLAS_EVENT_ERROR unix_ms={:?} active_cycle={} error={}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_millis()),
                driver.cycle.as_ref().is_some_and(|c| &c.root == root),
                error
            );
            let mut retirement_error = None;
            let writer_busy = matches!(error.body.detail(), se_types::Detail::AtlasResourceBudget(detail)
                if detail.resource == "Atlas home writer lease");
            if let Some(index) = driver.roots.iter().position(|r| &r.id == root) {
                if writer_busy {
                    // SQL mapping could not be borrowed, but the subscription
                    // is healthy. Consume this finite native wake and retain a
                    // full reconcile, so a later edit can wake us after unlock.
                    // Closing here lost that only event source; retaining an
                    // unread level-triggered wake would spin on the held lease.
                    let read_error = if let Some(native) = &driver.roots[index].native {
                        let mut bytes = [0; 16384];
                        native.watch.read(&mut bytes).err()
                    } else {
                        None
                    };
                    if let Some(read_error) = read_error {
                        let read_error = source_error("deferred watch read", read_error);
                        retirement_error = Some(match driver.retire_native(index, deadline) {
                            Ok(()) => read_error,
                            Err(retirement) => retain_failure(retirement, read_error),
                        });
                    }
                    driver.roots[index].requires_reconcile = true;
                } else {
                    retirement_error = driver.retire_native(index, deadline).err();
                }
            }
            if driver.cycle.as_ref().is_some_and(|c| &c.root == root) {
                driver.cycle = None;
            }
            controller.enqueue(
                root.clone(),
                SourceHint::Reconcile(ReconcileReason::WatchFailure),
            )?;
            return Err(match retirement_error {
                Some(retirement) => retain_failure(retirement, error),
                None => error,
            });
        }
    };
    let locks = sync_locks(controller)?;
    let count = hints.len();
    for hint in hints {
        controller.enqueue(root.clone(), hint)?;
    }
    Ok(count + locks)
}

fn retain_failure(primary: SeError, other: SeError) -> SeError {
    let native = primary
        .cause
        .as_ref()
        .map_or_else(String::new, ToString::to_string);
    let cause = std::io::Error::other(format!("{primary}; {native}; earlier failure: {other}"));
    primary.with_cause(cause)
}

/// Run source work and transfer newly observed checkout-lock state to the same
/// scheduler before it can publish. Callers pair this with `drive_events`.
pub fn drive_quantum(
    controller: &mut crate::atlas_runtime::NativeController<NativeRenewal>,
    duration: Duration,
) -> AtlasResult<Option<WorkReport>> {
    sync_locks(controller)?;
    let result = controller.work_quantum(duration);
    sync_locks(controller)?;
    result
}
fn sync_locks(
    controller: &mut crate::atlas_runtime::NativeController<NativeRenewal>,
) -> AtlasResult<usize> {
    let changes: Vec<_> = controller
        .runtime_mut()
        .driver_mut()
        .roots
        .iter_mut()
        .filter_map(|root| root.pending_lock.take().map(|held| (root.id.clone(), held)))
        .collect();
    let count = changes.len();
    for (root, held) in changes {
        controller.git_lock(&root, held)?;
    }
    Ok(count)
}
