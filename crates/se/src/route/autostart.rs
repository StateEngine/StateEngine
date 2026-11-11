//! Shared finite automatic runtime rendezvous for launch and native hooks.
//! No request is submitted here; authentication remains the forwarding step.
use super::{execute, files::Files};
use crate::{
    bootstrap::Bootstrap,
    config::Origin,
    runtime::host::{StartupFailure, StartupOrigin},
};
use se_host::client::lease::Deadline;
use se_proc::{NativeProcessApi, NativeProcessRuntime, RuntimeExitObservation};
use se_types::{Read, Result, SeError};
use std::time::Duration;

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) fn endpoint(
    cx: &Bootstrap,
    files: &Files,
    bound: &Deadline,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<se_host::EndpointRecord> {
    #[cfg(unix)]
    let expected = se_host::IpcEndpoint::UnixSocket(se_types::NativePath::from_local(
        crate::config::unix_socket_paths()?
            .expected_path(&cx.home)
            .map_err(|error| {
                se_core::scope::unreadable("expected runtime socket", &error.to_string())
                    .with_cause(error)
            })?,
    )?);
    #[cfg(unix)]
    let expected = Some(&expected);
    #[cfg(windows)]
    let expected = None;
    let configuration = match &cx.config.origin {
        Origin::File(path) => path.clone(),
        Origin::BuiltIn => cx.home.join("config.toml"),
    };
    let started = std::time::Instant::now();
    let mut failure: Option<Box<StartupFailure>> = None;
    let mut abort_requested = false;
    loop {
        if let Err(error) = bound.remaining() {
            let pending = SeError::new(se_types::Detail::RuntimeStartPending(
                se_types::details::RuntimeStartPending {
                    waited_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                },
            ))
            .with_cause(error);
            if let Some(failed) = failure {
                // Its public refusal already names the failed native phase and
                // startup log. Retaining it only as an internal cause hides both.
                let original = SeError {
                    body: failed.error.body.clone(),
                    cause: None,
                };
                return Err(retain(original, Some(failed)));
            }
            return Err(crate::runtime::host::startup_log::pending(
                &cx.home,
                pending,
                "the current runtime.lock holder to publish endpoint.json or release its lease; this request has not started a runtime child",
            ));
        }
        let route = match se_host::route_endpoint(&cx.home, expected) {
            Ok(route) => route,
            Err(error) => {
                // A held lease with no publication is a concurrent bootstrap
                // or writer. A malformed/mismatched present record still refuses.
                let unpublished = if error.code() == se_types::Code::StateConflict {
                    match execute::endpoint(files) {
                        Ok(Read::Absent { .. }) => true,
                        Ok(_) => false,
                        Err(read_error) => return Err(retain(read_error, failure)),
                    }
                } else {
                    false
                };
                if unpublished {
                    pause(bound);
                    continue;
                }
                return Err(retain(error, failure));
            }
        };
        match route {
            se_host::EndpointRoute::Live(endpoint) => {
                if failure
                    .as_ref()
                    .and_then(|failed| failed.child.as_ref())
                    .and_then(|child| child.identity())
                    .is_some_and(|identity| {
                        identity.pid.0 == endpoint.epoch.owner.fields().pid.get()
                    })
                {
                    // Our own published-but-unconfirmed owner is not a winning
                    // competitor. Keep its exact child/commit state for recovery.
                    if let Some(failed) = failure {
                        let error = SeError {
                            body: failed.error.body.clone(),
                            cause: None,
                        };
                        return Err(retain(error, Some(failed)));
                    }
                }
                match settle(&mut failure, &mut abort_requested) {
                    Ok(true) => return Ok(endpoint),
                    Ok(false) => pause(bound),
                    Err(error) => return Err(retain(error, failure)),
                }
            }
            se_host::EndpointRoute::Start { recovery } => {
                if let Some(failed) = failure {
                    // There is no winner holding the exclusive lease. Preserve
                    // the actual failed attempt rather than spawning repeatedly.
                    let error = SeError {
                        body: failed.error.body.clone(),
                        cause: None,
                    };
                    return Err(retain(error, Some(failed)));
                }
                let machine = super::identity::require_machine(files)?;
                match crate::runtime::host::start_with_origin(
                    &cx.home,
                    &configuration,
                    machine,
                    StartupOrigin::Automatic,
                    bound,
                ) {
                    Ok(started) => {
                        if let Some(recovery) = recovery {
                            diagnostic(&format!(
                                "Retained stale runtime endpoint at {:?}",
                                recovery.retained
                            ))
                            .map_err(|error| {
                                se_core::scope::unreadable(
                                    "automatic host startup diagnostic",
                                    &error.to_string(),
                                )
                                .with_cause(error)
                            })?;
                        }
                        return Ok(started.endpoint);
                    }
                    Err(failed) => failure = Some(failed),
                }
            }
        }
    }
}
fn pause(bound: &Deadline) {
    std::thread::park_timeout(
        bound
            .at()
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_millis(10)),
    );
}
fn settle(failure: &mut Option<Box<StartupFailure>>, abort_requested: &mut bool) -> Result<bool> {
    let Some(child) = failure.as_mut().and_then(|failure| failure.child.as_mut()) else {
        return Ok(true);
    };
    // A distinct winner owns the home's exclusive lease. Revoke only our
    // retained uncommitted bootstrap child; an ambiguous commit stays pinned.
    if !child.commit_pending() && !*abort_requested {
        NativeProcessRuntime::abort_runtime(child).map_err(|error| {
            se_core::scope::unreadable("competing startup cancellation", &format!("{error:?}"))
        })?;
        *abort_requested = true;
    }
    match NativeProcessRuntime::witness_runtime(child).map_err(|error| {
        se_core::scope::unreadable("competing startup child", &format!("{error:?}"))
    })? {
        RuntimeExitObservation::Pending { .. } => Ok(false),
        RuntimeExitObservation::Exited(witness) => {
            NativeProcessRuntime::release_runtime(child, &witness).map_err(|error| {
                se_core::scope::unreadable("competing startup child release", &format!("{error:?}"))
            })?;
            if let Some(failure) = failure {
                failure.child = None;
            }
            Ok(true)
        }
    }
}
fn retain(error: SeError, failure: Option<Box<StartupFailure>>) -> SeError {
    match failure {
        Some(failure) => error.with_cause(RetainedStartup(failure)),
        None => error,
    }
}
#[derive(Debug)]
struct RetainedStartup(Box<StartupFailure>);
impl std::fmt::Display for RetainedStartup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.error.fmt(f)
    }
}
impl std::error::Error for RetainedStartup {}
