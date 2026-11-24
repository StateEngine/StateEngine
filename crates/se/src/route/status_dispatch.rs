//! Status dispatch: this process's local build stays authoritative while a
//! concurrent daemon observation, asked for only when its answer would be
//! used, may add live runtime facts.
use super::{
    execute::{self, RouteContext},
    files::Files,
};
use crate::bootstrap::Bootstrap;
use se_core::{
    ops::{AnyOp, AnyOutput},
    scope,
    store_error::store_error,
};
use se_store::Snapshot;
use se_types::{Read, Result, SeError};
#[cfg(any(windows, target_os = "macos"))]
use std::time::Duration;

/// One rule: remote work starts only when the merged answer would be used.
///
/// A whole-machine read never merges a host observation, a home with no
/// published endpoint has nothing to ask, and a removed project reports its
/// local removal view without consulting a host at all. Every exclusion here is
/// knowable before the build, which is what lets the remaining request overlap
/// it instead of running before it.
fn uses_host_observation<S: Snapshot>(
    cx: &Bootstrap,
    files: &Files,
    snapshot: &mut S,
    caller: &super::admit::Caller,
) -> bool {
    if cx.selections.status_all {
        return false;
    }
    if let se_store::Scope::Project(project) = &caller.admission.scope
        && let Ok(Read::Present { value }) = snapshot.project(project.clone())
        && se_core::ops::project_remove::removed_view(&value)
            .ok()
            .flatten()
            .is_some()
    {
        return false;
    }
    matches!(execute::endpoint(files), Ok(Read::Present { .. }))
}

/// A daemon answer in flight, owned by the frame that started it.
struct DaemonObservation {
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
fn daemon_observation_start(request: Result<super::hosted::StatusRequest>) -> DaemonObservation {
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
    fn finish(self, used: bool) -> Result<Option<Result<AnyOutput>>> {
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
fn daemon_answer_is_used(cx: &Bootstrap, output: &AnyOutput) -> bool {
    if cx.selections.status_all {
        return false;
    }
    match output {
        AnyOutput::ProjectStatus(status) => {
            status.value.runtime.state == "running" && status.value.removal.is_none()
        }
        _ => false,
    }
}

fn merge_status_pending(
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
fn early_status(
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
fn complete_deferred_status(
    cx: &Bootstrap,
    files: &Files,
    output: &mut AnyOutput,
    early: &Option<Result<AnyOutput>>,
    deferred: bool,
) {
    if deferred {
        let watched = early.as_ref().and_then(|answer| answer.as_ref().ok());
        super::status::complete_deferred_git(cx, files, output, watched);
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn finish_status_observation(
    pending: Option<DaemonObservation>,
    early: Option<Result<AnyOutput>>,
    cx: &Bootstrap,
    output: &AnyOutput,
) -> Result<Option<Result<AnyOutput>>> {
    if early.is_some() {
        return Ok(if daemon_answer_is_used(cx, output) {
            early
        } else {
            None
        });
    }
    Ok(pending
        .map(|pending| pending.finish(daemon_answer_is_used(cx, output)))
        .transpose()?
        .flatten())
}

pub(super) fn dispatch(
    req: RouteContext<'_>,
    op: &AnyOp,
    mut snapshot: se_store::SqliteSnapshot,
    owner: Option<Read<se_store::RuntimeOwnerHead>>,
) -> Result<AnyOutput> {
    let RouteContext {
        cx,
        files,
        reader,
        caller,
        selections,
        observation_deadline,
    } = req;
    // Ask the daemon concurrently with this process's own build. The local
    // build stays authoritative, so status is still honest when the daemon
    // is absent or stale; only the wall time changes, from the sum of the
    // two to the longer of them.
    let ask_daemon = uses_host_observation(cx, files, &mut snapshot, caller);
    // The request owns everything it needs, so it runs on an unscoped thread
    // and this frame never waits for it unless the answer is used below. A
    // local error, a removed project or `--all` therefore returns at once
    // instead of joining a daemon that is slow, paused or gone; the thread
    // prints nothing and holds no lock this path needs.
    let pending = ask_daemon.then(|| {
        daemon_observation_start(super::hosted::StatusRequest::prepare(
            cx, files, caller, selections,
        ))
    });
    #[cfg(any(windows, target_os = "macos"))]
    let defer_git = pending.is_some() && matches!(op, AnyOp::ProjectStatus(input) if !input.fresh);
    #[cfg(not(any(windows, target_os = "macos")))]
    let defer_git = false;
    let include_temp = matches!(op, AnyOp::ProjectStatus(input) if input.include_temp);
    let result = super::status::observe_snapshot_watched(
        cx,
        &mut snapshot,
        owner,
        files,
        &caller.admission,
        super::status::ObserveOptions {
            watched: None,
            defer_git,
            include_temp,
        },
    );
    #[cfg(any(windows, target_os = "macos"))]
    let early = early_status(&pending, op, defer_git && result.is_ok());
    let result = result.and_then(|mut output| {
        #[cfg(any(windows, target_os = "macos"))]
        complete_deferred_status(cx, files, &mut output, &early, defer_git);
        #[cfg(not(any(windows, target_os = "macos")))]
        let _ = &mut output;
        super::session_observation::prepare(
            output,
            &mut snapshot,
            &caller.admission,
            observation_deadline,
        )
    });
    let prepared = execute::finish_read(result, snapshot.close().map_err(|e| store_error(&e)))?;
    let mut output = super::session_observation::finish(prepared, &cx.home)?;
    // None means nothing was asked, so there is nothing to merge and no
    // invented error: a read that never needs the host behaves exactly as it
    // did before this overlap existed.
    #[cfg(any(windows, target_os = "macos"))]
    let observed = finish_status_observation(pending, early, cx, &output)?;
    #[cfg(not(any(windows, target_os = "macos")))]
    let observed = pending
        .map(|pending| pending.finish(daemon_answer_is_used(cx, &output)))
        .transpose()?
        .flatten();
    super::status::host_peers(&mut output, observed.as_ref(), &caller.admission);
    let mut service_observation = None;
    if let Some(observed) = observed
        && let AnyOutput::ProjectStatus(status) = &mut output
    {
        // The direct native/store witness stays authoritative for status.
        // The host's Atlas metadata and retained session faults come from the
        // request that was already in flight during the build; the host is
        // never bootstrapped here.
        super::status::merge_resources(&mut status.value.runtime, &observed);
        status.value.atlas = match &observed {
            Ok(AnyOutput::ProjectStatus(live)) => {
                merge_status_pending(&mut status.value.pending, &live.value.pending, op);
                live.value.atlas.clone()
            }
            Ok(_) => se_core::ops::status::atlas_view(Err(scope::unreadable(
                "Atlas status",
                "the host returned a different operation family",
            ))),
            Err(error) => {
                se_core::ops::status::atlas_view(Err(se_types::SeError::from(error.body.clone())))
            }
        };
        service_observation = Some(observed);
    }
    if let Some(live) = service_observation {
        output = super::session_observation::merge_runtime_observation(output, live)?;
    }
    super::status::finish(cx, reader, output, &caller.admission)
}
