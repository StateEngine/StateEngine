use super::schedule::sync_locks;
use super::*;
#[cfg(feature = "cold-watch-probe")]
impl NativeRenewal {
    pub fn probe_take_full_reconcile(&self) -> bool {
        crate::atlas_watch_probe::take_full_reconcile()
    }
}

#[cfg(all(windows, feature = "cold-watch-probe"))]
impl NativeRenewal {
    pub fn probe_retained_event(&self, root: &RootId, path: Option<&str>) -> AtlasResult<()> {
        let capture = self
            .cold_capture
            .as_ref()
            .filter(|capture| &capture.id == root)
            .ok_or_else(|| source_error("cold watch probe", "no retained watch"))?;
        let watch = &capture.native.watch;
        let end = Instant::now() + Duration::from_secs(8);
        loop {
            watch
                .synchronize(Duration::from_secs(1))
                .map_err(|error| source_error("cold watch probe", error))?;
            let (seen, queued, lost) = watch
                .probe_pending(path)
                .map_err(|error| source_error("cold watch probe", error))?;
            if seen {
                eprintln!(
                    "cold watch witnessed before adoption: {path:?} queued={queued} lost={lost}"
                );
                return Ok(());
            }
            if Instant::now() >= end {
                return Err(source_error(
                    "cold watch probe",
                    format!(
                        "stimulus {path:?} absent before adoption; queued={queued} lost={lost}"
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl crate::atlas_runtime::RenewalDriver for NativeRenewal {
    #[cfg(windows)]
    fn begin_cold_capture(&mut self, source: &Source, policy: &AtlasPolicy) -> AtlasResult<()> {
        if self.cold_capture.is_none() {
            let used = self.mappings.len()
                + self
                    .roots
                    .iter()
                    .filter_map(|root| root.native.as_ref())
                    .filter_map(|native| native.metadata.as_ref())
                    .map(metadata::Watches::len)
                    .sum::<usize>();
            #[cfg(feature = "cold-watch-probe")]
            let used = if crate::atlas_watch_probe::event(source, "capacity")? {
                0
            } else {
                used
            };
            self.cold_capture = cold_capture::Capture::start(source, policy, used)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    fn cold_capture_available(&self, root: &RootId) -> bool {
        self.cold_capture
            .as_ref()
            .is_some_and(|capture| &capture.id == root)
    }
    #[cfg(windows)]
    fn activate_cold_capture(&mut self, root: &RootId) -> AtlasResult<()> {
        let capture = self
            .cold_capture
            .as_mut()
            .filter(|capture| &capture.id == root)
            .ok_or_else(|| source_error("cold source watch", "capture disappeared"))?;
        let signal = self.signal.clone();
        capture
            .native
            .watch
            .set_signal(std::sync::Arc::new(move || signal.notify_one()))
            .map_err(|error| source_error("cold source readiness", error))?;
        capture.activated = true;
        self.signal.notify_one();
        Ok(())
    }
    #[cfg(windows)]
    fn discard_cold_capture(&mut self, root: &RootId) -> AtlasResult<()> {
        if let Some(capture) = self
            .cold_capture
            .as_mut()
            .filter(|capture| &capture.id == root)
        {
            let timeout = Duration::from_millis(200);
            capture
                .native
                .watch
                .shutdown(timeout)
                .map_err(|error| crate::atlas_parse::cleanup_error(error, timeout))?;
            self.cold_capture = None;
        }
        Ok(())
    }
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
    let (hints, event_deadline) = match controller.runtime_mut().poll_events_classified(
        root,
        now + std::time::Duration::from_secs(5),
        Some(budget),
    ) {
        Ok(result) => result,
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
    #[cfg(windows)]
    let pending = finish_catchup(controller, root, event_deadline, pending)?;
    #[cfg(not(windows))]
    let _ = event_deadline;
    controller.set_watch_pending(root, pending)?;
    Ok(count + locks)
}

#[cfg(windows)]
fn finish_catchup(
    controller: &mut crate::atlas_runtime::NativeController<NativeRenewal>,
    root: &RootId,
    deadline: Instant,
    mut pending: bool,
) -> AtlasResult<bool> {
    let caught = (|| -> AtlasResult<()> {
        if let Some(item) = controller
            .runtime_mut()
            .driver_mut()
            .roots
            .iter_mut()
            .find(|item| &item.id == root)
            && item.catching_up == Catchup::Pending
        {
            timely(deadline)?;
            let native = item
                .native
                .as_ref()
                .ok_or_else(|| source_error("cold source watch", "closed"))?;
            native
                .watch
                .synchronize(deadline.saturating_duration_since(Instant::now()))
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::TimedOut {
                        limit("renewal work deadline", 1, 0)
                    } else {
                        source_error("cold watch barrier", error)
                    }
                })?;
            timely(deadline)?;
            if !pending {
                let mut buffer = [0u8; 4096];
                let count = native
                    .watch
                    .read_one(&mut buffer)
                    .map_err(|error| source_error("cold watch queue", error))?;
                if count != 0 {
                    item.pending_events = Some(PendingEvents {
                        bytes: buffer[..count].to_vec(),
                        next: 0,
                        hints: Vec::new(),
                    });
                    pending = true;
                }
            }
            if !pending {
                item.catching_up = Catchup::Complete;
            }
        }
        Ok(())
    })();
    if let Err(error) = caught {
        if se_atlas::controller::quantum_expired(&error) {
            return Err(error);
        }
        let driver = controller.runtime_mut().driver_mut();
        let retirement = driver
            .roots
            .iter()
            .position(|item| &item.id == root)
            .and_then(|index| {
                driver
                    .retire_native(index, Instant::now() + Duration::from_secs(5))
                    .err()
            });
        controller.enqueue(
            root.clone(),
            SourceHint::Reconcile(ReconcileReason::WatchFailure),
        )?;
        controller.set_watch_pending(root, false)?;
        return Err(match retirement {
            Some(retirement) => retain_failure(retirement, error),
            None => error,
        });
    }
    Ok(pending)
}

fn retain_failure(primary: SeError, other: SeError) -> SeError {
    let native = primary
        .cause
        .as_ref()
        .map_or_else(String::new, ToString::to_string);
    let cause = std::io::Error::other(format!("{primary}; {native}; earlier failure: {other}"));
    primary.with_cause(cause)
}
