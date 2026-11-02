//! Native hook writes always use a host. A cold call gets one finite bootstrap
//! clock, joins a concurrent starter and never writes through a direct store.
use super::{execute, files::Files};
use crate::bootstrap::Bootstrap;
use se_types::{Result, SeError};
#[cfg(any(target_os = "linux", windows))]
use {
    crate::{
        config::Origin,
        runtime::host::{StartupFailure, StartupOrigin},
    },
    se_host::client::{ClientOptions, lease::Deadline},
    se_proc::{NativeProcessApi, NativeProcessRuntime, RuntimeExitObservation},
    se_types::Read,
    std::{sync::Arc, time::Duration},
};

#[cfg(any(target_os = "linux", windows))]
pub fn forward(
    cx: &Bootstrap,
    files: &Files,
    input: se_host::ClaudeHookInput,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<se_core::ops::AnyOutput> {
    if cx.session.is_none() {
        return Err(SeError::new(se_types::Detail::SessionRequired(
            se_types::details::SessionRequired {
                op: "hook.claude".into(),
            },
        )));
    }
    let mut options = execute::options();
    options.timeout = Duration::from_secs(10);
    let bound = Deadline::from_options(&options)?;
    let target = endpoint(cx, files, &bound, diagnostic)?;
    // Authenticated discovery and frame exchange use the original clock too.
    se_proc::native_ipc::restore_image_cache(&cx.home, target.image_sha256, &bound.native_bound())
        .map_err(|error| {
            se_core::scope::unreadable("protected executable cache", &error.to_string())
                .with_cause(error)
        })?;
    crate::ipc::forward_hook(
        &target,
        execute::credential(cx, files)?,
        input,
        &ClientOptions {
            expected_generation: Some(target.generation),
            timeout: bound.remaining()?,
            cancelled: Arc::clone(&bound.native_bound().cancelled),
        },
    )
}

#[cfg(any(target_os = "linux", windows))]
fn endpoint(
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
    #[cfg(windows)]
    let expected = se_host::runtime_endpoint_address(&cx.home)?;
    let configuration = match &cx.config.origin {
        Origin::File(path) => path.clone(),
        Origin::BuiltIn => cx.home.join("config.toml"),
    };
    let mut failure: Option<Box<StartupFailure>> = None;
    let mut abort_requested = false;
    loop {
        if let Err(error) = bound.remaining() {
            return Err(retain(
                SeError::new(se_types::Detail::RuntimeStartPending(
                    se_types::details::RuntimeStartPending { waited_ms: 10_000 },
                ))
                .with_cause(error),
                failure,
            ));
        }
        let route = match se_host::route_endpoint(&cx.home, &expected) {
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
                                    "hook startup diagnostic",
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
#[cfg(any(target_os = "linux", windows))]
fn pause(bound: &Deadline) {
    std::thread::park_timeout(
        bound
            .at()
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_millis(10)),
    );
}
#[cfg(any(target_os = "linux", windows))]
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
#[cfg(any(target_os = "linux", windows))]
fn retain(error: SeError, failure: Option<Box<StartupFailure>>) -> SeError {
    match failure {
        Some(failure) => error.with_cause(RetainedStartup(failure)),
        None => error,
    }
}
#[cfg(any(target_os = "linux", windows))]
#[derive(Debug)]
struct RetainedStartup(Box<StartupFailure>);
#[cfg(any(target_os = "linux", windows))]
impl std::fmt::Display for RetainedStartup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.error.fmt(f)
    }
}
#[cfg(any(target_os = "linux", windows))]
impl std::error::Error for RetainedStartup {}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn forward(
    _cx: &Bootstrap,
    _files: &Files,
    _input: se_host::ClaudeHookInput,
    _diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<se_core::ops::AnyOutput> {
    Err(SeError::new(se_types::Detail::FeatureUnavailable(
        se_types::details::FeatureUnavailable {
            subject: "hook host bootstrap".into(),
            reason: "native detached runtime bootstrap is not available on this platform".into(),
            next_step: "Use a supported Linux or Windows installation for managed Claude capture"
                .into(),
        },
    )))
}
