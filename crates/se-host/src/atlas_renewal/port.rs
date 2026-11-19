use super::schedule::sync_locks;
use super::*;
impl crate::atlas_runtime::RenewalDriver for NativeRenewal {
    fn bind_parser_image(&mut self, image: &std::path::Path) -> AtlasResult<()> {
        self.parser.bind_image(image);
        Ok(())
    }
    fn release_parser(&mut self, deadline: Instant) -> AtlasResult<()> {
        self.parser.close(deadline)
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

/// Preserve native readiness and consumed event bytes until lookup succeeds.
/// Writer admission has its own bound; the supplied deadline bounds event work
/// after admission, so opening the cache cannot consume the event allowance.
pub fn drive_events(
    controller: &mut crate::atlas_runtime::NativeController<NativeRenewal>,
    root: &RootId,
    deadline: Instant,
) -> AtlasResult<usize> {
    controller.set_watch_pending(root, true)?;
    let now = Instant::now();
    let budget = deadline.saturating_duration_since(now);
    if budget.is_zero() {
        return Err(se_atlas::cache::connection::timeout_phase(
            "event drain admission",
            budget,
            budget,
        ));
    }
    let hints = match controller.runtime_mut().poll_events_classified(
        root,
        now + std::time::Duration::from_secs(5),
        Some(budget),
    ) {
        Ok((hints, _)) => hints,
        Err(crate::atlas_runtime::PollEventsFailure::Admission(error)) => return Err(error),
        Err(crate::atlas_runtime::PollEventsFailure::Driver(error)) => {
            let watch_died = matches!(error.body.detail(), Detail::AtlasSourceUnreadable(detail)
                if detail.path == "watch event read" || detail.path == "watch mapping lost");
            let retryable = se_atlas::controller::quantum_expired(&error)
                || matches!(error.body.detail(), Detail::AtlasResourceBudget(detail)
                    if detail.resource == "Atlas home writer lease");
            let consumed = controller
                .runtime_mut()
                .driver_mut()
                .roots
                .iter()
                .find(|item| &item.id == root)
                .is_some_and(|item| item.pending_events.is_some());
            if !watch_died && (retryable || !consumed) {
                return Err(error);
            }
            let driver = controller.runtime_mut().driver_mut();
            let mut retirement_error = None;
            if let Some(index) = driver.roots.iter().position(|r| &r.id == root) {
                retirement_error = driver
                    .retire_native(index, Instant::now() + std::time::Duration::from_secs(5))
                    .err();
            }
            controller.enqueue(
                root.clone(),
                SourceHint::Reconcile(ReconcileReason::WatchFailure),
            )?;
            controller.set_watch_pending(root, false)?;
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
    let issue = controller
        .runtime_mut()
        .driver_mut()
        .roots
        .iter()
        .find(|item| &item.id == root)
        .and_then(|item| {
            item.reasons.iter().copied().find(|reason| {
                matches!(
                    reason,
                    CoverageReason::ReadFailure
                        | CoverageReason::ByteLimit
                        | CoverageReason::UnsupportedEncoding
                )
            })
        });
    if let Some(issue) = issue {
        controller.note_watch_issue(root, issue)?;
    }
    let pending = controller
        .runtime_mut()
        .driver_mut()
        .roots
        .iter()
        .find(|item| &item.id == root)
        .is_some_and(|item| item.pending_events.is_some());
    controller.set_watch_pending(root, pending)?;
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
