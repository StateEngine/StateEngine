//! Assemble optional host status without blocking local inventory.
use super::*;

pub(super) fn uses_host_observation<S: Snapshot>(
    files: &Files,
    snapshot: &mut S,
    caller: &admit::Caller,
) -> bool {
    if let se_store::Scope::Project(project) = &caller.admission.scope
        && let Ok(Read::Present { value }) = snapshot.project(project.clone())
        && se_core::ops::project_remove::removed_view(&value)
            .ok()
            .flatten()
            .is_some()
    {
        return false;
    }
    matches!(endpoint(files), Ok(Read::Present { .. }))
}

/// A daemon answer in flight, owned by the frame that started it.
pub(super) struct DaemonObservation {
    answer: std::sync::mpsc::Receiver<Result<AnyOutput>>,
    /// A failure to start the read at all, which no answer can carry.
    start_failure: Option<SeError>,
}

/// Start the one bounded status read off this thread. It owns the request's
/// endpoint, credential, presence and options, so it neither borrows the
/// caller's snapshot nor holds a lock this path needs.
///
/// A request that could not be prepared keeps its error instead of failing the
/// command: the answer only ever reaches the merge, so a home whose endpoint is
/// unreadable or absent reports exactly what it reported before this overlap.
pub(super) fn daemon_observation_start(
    request: Result<crate::route::hosted::StatusRequest>,
) -> DaemonObservation {
    let (answer, receiver) = std::sync::mpsc::channel();
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            let _ = answer.send(Err(error));
            return DaemonObservation {
                answer: receiver,
                start_failure: None,
            };
        }
    };
    let sender = answer.clone();
    let spawned = std::thread::Builder::new()
        .name("status-observation".into())
        .spawn(move || {
            // The receiver may already be gone; the answer is then dropped unread.
            let _ = sender.send(request.run());
        });
    // A thread that could not start leaves that fact behind. It is reported even
    // when the answer would have been discarded: the caller asked for an
    // observation, and "it never ran" is not the same as "it said nothing".
    let start_failure = match spawned {
        Ok(_) => None,
        Err(error) => Some(
            scope::unreadable("status daemon observation", &error.to_string()).with_cause(error),
        ),
    };
    // The extra sender is dropped here, so a thread that ended without sending
    // reads as disconnected rather than as a wait that never returns.
    drop(answer);
    DaemonObservation {
        answer: receiver,
        start_failure,
    }
}

impl DaemonObservation {
    #[cfg(any(windows, target_os = "macos"))]
    fn early(&self, timeout: Duration) -> Option<Result<AnyOutput>> {
        if self.start_failure.is_some() {
            return None;
        }
        self.answer.recv_timeout(timeout).ok()
    }

    /// Whole-home inventory must remain available even if the live host stalls.
    /// Keep an answer already received; otherwise report that live details were
    /// not observed instead of waiting for the host's deadline.
    pub(super) fn finish_if_ready(self) -> Result<AnyOutput> {
        if let Some(error) = self.start_failure {
            return Err(error);
        }
        match self.answer.try_recv() {
            Ok(answer) => answer,
            Err(std::sync::mpsc::TryRecvError::Empty) => Err(scope::unreadable(
                "live runtime details",
                "the host did not answer during the local inventory; run se status in the project for live spawner details",
            )),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Err(scope::unreadable(
                "status daemon observation",
                "the observation thread ended without an answer",
            )),
        }
    }
    /// Receive the answer only when `used`, which is the one decision this frame
    /// makes about it.
    ///
    /// A read that never started is reported through the same channel as a read
    /// that failed, so the merge still publishes the project status it observed
    /// locally and marks only the daemon facts unreadable. When the answer is
    /// unused there is no merge to carry it, so the failure is returned: the
    /// caller asked for an observation, and "it never ran" is not "it said
    /// nothing". An unused started read is dropped unread and ends on its own
    /// deadline, so nothing waits and nothing leaks.
    pub(super) fn finish(self, used: bool) -> Result<Option<Result<AnyOutput>>> {
        match (used, self.start_failure) {
            (false, Some(error)) => Err(error),
            (_, failure) => Ok(used.then(|| match failure {
                Some(error) => Err(error),
                None => self.answer.recv().unwrap_or_else(|_| {
                    Err(scope::unreadable(
                        "status daemon observation",
                        "the observation thread ended without an answer",
                    ))
                }),
            })),
        }
    }
}

/// The one rule for receiving the answer: it is collected only when the merged
/// result would use it. These are the same conditions the merge applies, so a
/// path that discards the answer never waits for it.
pub(super) fn daemon_answer_is_used(output: &AnyOutput) -> bool {
    match output {
        AnyOutput::ProjectStatus(status) => {
            status.value.runtime.state == "running" && status.value.removal.is_none()
        }
        _ => false,
    }
}

pub(super) fn merge_status_pending(
    target: &mut Vec<se_core::ops::PendingFact>,
    incoming: &[se_core::ops::PendingFact],
    operation: &AnyOp,
) {
    for pending in incoming {
        #[cfg(any(windows, target_os = "macos"))]
        if matches!(operation, AnyOp::ProjectStatus(input) if input.fresh)
            && pending.what == "repository watch"
        {
            continue;
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        let _ = operation;
        if !target.iter().any(|known| {
            known.what == pending.what
                && known.since == pending.since
                && known.detail == pending.detail
        }) {
            target.push(pending.clone());
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn early_status(
    pending: &Option<DaemonObservation>,
    op: &AnyOp,
    eligible: bool,
) -> Option<Result<AnyOutput>> {
    if eligible && matches!(op, AnyOp::ProjectStatus(input) if !input.fresh) {
        pending
            .as_ref()
            .and_then(|pending| pending.early(Duration::from_millis(15)))
    } else {
        None
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn complete_deferred_status(
    cx: &Bootstrap,
    files: &Files,
    output: &mut AnyOutput,
    early: &Option<Result<AnyOutput>>,
    deferred: bool,
) {
    if deferred {
        let watched = early.as_ref().and_then(|answer| answer.as_ref().ok());
        crate::route::status::complete_deferred_git(cx, files, output, watched);
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn finish_status_observation(
    pending: Option<DaemonObservation>,
    early: Option<Result<AnyOutput>>,
    cx: &Bootstrap,
    output: &AnyOutput,
) -> Result<Option<Result<AnyOutput>>> {
    if early.is_some() {
        return Ok(if daemon_answer_is_used(output) {
            early
        } else {
            None
        });
    }
    Ok(pending
        .map(|pending| {
            if cx.selections.status_all {
                Ok(daemon_answer_is_used(output).then(|| pending.finish_if_ready()))
            } else {
                pending.finish(daemon_answer_is_used(output))
            }
        })
        .transpose()?
        .flatten())
}
