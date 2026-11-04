//! Explicit host control through the native bootstrap and authenticated fixed
//! stop protocol. No connection failure permits a direct-write fallback.
use super::{admit::Caller, execute, files::Files};
#[cfg(any(target_os = "linux", windows))]
use super::{process, status};
use crate::bootstrap::Bootstrap;
#[cfg(any(target_os = "linux", windows))]
use crate::config::Origin;
use se_core::{ops::*, scope};
use se_host::client::BlockingIpcClient;
#[cfg(any(target_os = "linux", windows))]
use se_host::client::lease::Deadline;
#[cfg(any(target_os = "linux", windows))]
use se_types::Read;
use se_types::{Result, SeError};
#[cfg(any(target_os = "linux", windows))]
use std::num::NonZeroU32;
#[cfg(any(target_os = "linux", windows))]
#[path = "runtime/completion.rs"]
mod completion;
#[path = "runtime/stops.rs"]
mod stops;

#[cfg(any(target_os = "linux", windows))]
pub fn up(
    cx: &Bootstrap,
    files: &Files,
    caller: &Caller,
    _input: RuntimeUp,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    if caller.owner.is_none() {
        return Err(SeError::invalid("runtime owner", "native owner authority"));
    }
    let options = execute::options();
    let bound = Deadline::from_options(&options)?;
    #[cfg(unix)]
    let expected = se_host::IpcEndpoint::UnixSocket(se_types::NativePath::from_local(
        crate::config::unix_socket_paths()?
            .expected_path(&cx.home)
            .map_err(|error| {
                scope::unreadable("expected runtime socket address", &error.to_string())
                    .with_cause(error)
            })?,
    )?);
    #[cfg(windows)]
    let expected = se_host::runtime_endpoint_address(&cx.home)?;
    let (endpoint, process, endpoint_recovery) = match se_host::route_endpoint(&cx.home, &expected)?
    {
        se_host::EndpointRoute::Live(value) => {
            BlockingIpcClient::connect_authenticated(
                &value,
                execute::credential(cx, files)?,
                NonZeroU32::new(se_host::client::wire::DEFAULT_REPLY_BYTES)
                    .ok_or_else(|| SeError::invalid("runtime reply budget", "positive"))?,
                &options,
            ).map_err(|error| {
                if error.code() == se_types::Code::IpcUnavailable {
                    SeError::new(se_types::Detail::StateConflict(se_types::details::StateConflict {
                        subject: cx.home.join("runtime.lock").display().to_string(),
                        reason: format!("the runtime lease is held but its endpoint could not be authenticated: {error}"),
                        next_step: "Run se down for this same data home before retrying se up; the endpoint and live host were preserved.".into(),
                    })).with_cause(error)
                } else { error }
            })?;
            let process = process::observe(&value, &bound)?;
            (value, process, None)
        }
        se_host::EndpointRoute::Start { recovery } => {
            let (endpoint, process) = start(cx, files, &bound, diagnostic).map_err(|error| {
                if let Some(retained) = &recovery {
                    let retained_path = match retained.retained.to_local() {
                        Ok(path) => path.display().to_string(),
                        Err(path_error) => format!("{:?} (path decoding failed: {path_error})", retained.retained),
                    };
                    SeError::new(se_types::Detail::StateConflict(se_types::details::StateConflict {
                        subject: cx.home.display().to_string(),
                        reason: format!("Retained stale endpoint {} as {retained_path}, but the runtime startup response could not be completed: {error}", cx.home.join("endpoint.json").display()),
                        next_step: "Keep the retained endpoint record and run se status for this same home before retrying se up; use se down first if another host is running.".into(),
                    })).with_cause(error)
                } else { error }
            })?;
            (endpoint, process, recovery)
        }
    };
    Ok(RuntimeStart {
        state: "running".into(),
        process,
        generation: endpoint.generation.get(),
        endpoint: status::endpoint_name(&endpoint)?,
        endpoint_recovery,
    }
    .into())
}
/// The public CLI keeps its original process as the sole standalone host.
#[cfg(any(target_os = "linux", windows))]
pub fn foreground(cx: &Bootstrap, ready: &mut dyn FnMut(AnyOutput) -> Result<()>) -> Result<u8> {
    let setup = super::setup::inspect_phase(
        &cx.home,
        se_core::ops::receipt::timestamp(execute::now_us()?)?,
    )?;
    let super::setup::Setup::Present((files, (reader, phase))) = setup else {
        return Err(super::setup::required(cx));
    };
    let admitted = super::admit::observe(cx, &phase, &files);
    let closed = phase
        .close()
        .map_err(|error| se_core::store_error::store_error(&error));
    let caller = match (admitted, closed) {
        (Ok(caller), Ok(())) => caller,
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(close)) => return Err(error.with_cause(close)),
    };
    if caller.owner.is_none() {
        return Err(SeError::invalid("runtime owner", "native owner authority"));
    }
    let machine = super::identity::require_machine(&files)?;
    let configuration = match &cx.config.origin {
        Origin::File(path) => path.clone(),
        Origin::BuiltIn => cx.home.join("config.toml"),
    };
    drop(reader);
    drop(files);
    crate::runtime::host::foreground(cx.home.clone(), configuration, machine, &mut |listener| {
        let endpoint = listener.endpoint();
        let bound = Deadline::from_options(&execute::options())?;
        ready(
            RuntimeStart {
                state: "running".into(),
                process: process::observe(endpoint, &bound)?,
                generation: endpoint.generation.get(),
                endpoint: status::endpoint_name(endpoint)?,
                endpoint_recovery: listener.endpoint_recovery().cloned(),
            }
            .into(),
        )
    })
}

#[cfg(any(target_os = "linux", windows))]
fn start(
    cx: &Bootstrap,
    files: &Files,
    bound: &Deadline,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<(se_host::EndpointRecord, ProcessView)> {
    let configuration = match &cx.config.origin {
        Origin::File(path) => path.clone(),
        Origin::BuiltIn => cx.home.join("config.toml"),
    };
    let machine = super::identity::require_machine(files)?;
    match crate::runtime::host::start(&cx.home, &configuration, machine, bound) {
        Ok(started) => {
            let started: crate::runtime::host::StartedHost = started;
            let process = process::from_identity(&started.ready.identity, bound)?;
            if !matches!(started.detachment_record, Read::Present { .. }) {
                diagnostic(&format!(
                    "Host is running; its protected detachment observation needs retry: {:?}",
                    started.detachment_record
                ))
                .map_err(|error| {
                    scope::unreadable("startup diagnostic", &error.to_string()).with_cause(error)
                })?;
            }
            Ok((started.endpoint, process))
        }
        Err(failure) => {
            let body = failure.error.body.clone();
            Err(SeError {
                body,
                cause: Some(Box::new(RetainedStartup(failure))),
            })
        }
    }
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn up(
    _cx: &Bootstrap,
    _files: &Files,
    _caller: &Caller,
    _input: RuntimeUp,
    _diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    Err(SeError::new(se_types::Detail::FeatureUnavailable(
        se_types::details::FeatureUnavailable {
            subject: "detached runtime startup on macOS".into(),
            reason: "this build implements detached host and process supervision only on Linux and Windows".into(),
            next_step: "Use se init, se status and direct saved-state operations on macOS; use a Linux or Windows installation for se up and hosted agent work".into(),
        },
    )))
}

#[cfg(any(target_os = "linux", windows))]
#[derive(Debug)]
struct RetainedStartup(Box<crate::runtime::host::StartupFailure>);
#[cfg(any(target_os = "linux", windows))]
impl std::fmt::Display for RetainedStartup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.error.fmt(f)
    }
}
#[cfg(any(target_os = "linux", windows))]
impl std::error::Error for RetainedStartup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0.error)
    }
}

pub fn down(files: &Files, input: RuntimeDown) -> Result<AnyOutput> {
    let options = execute::options();
    let endpoint = scope::require_present(
        execute::endpoint(files)?,
        "a live authenticated runtime endpoint for graceful down",
        "Run se status for this same data home and verify its recorded host; endpoint absence alone does not prove the host stopped.",
    )?;
    down_endpoint(files, &endpoint, input, &options)
}
pub(super) fn down_endpoint(
    files: &Files,
    endpoint: &se_host::EndpointRecord,
    input: RuntimeDown,
    options: &se_host::client::ClientOptions,
) -> Result<AnyOutput> {
    use se_host::client::endpoint::{RuntimeStopFact as Fact, RuntimeStopOutcome};
    let bound = Deadline::from_options(options)?;
    let mut options = se_host::client::ClientOptions {
        expected_generation: options.expected_generation,
        timeout: options.timeout,
        cancelled: options.cancelled.clone(),
    };
    let now = execute::now_us()?;
    let deadline = now
        .checked_add(
            i64::try_from(options.timeout.as_micros())
                .map_err(|_| SeError::invalid("stop deadline", "representable microseconds"))?,
        )
        .ok_or_else(|| SeError::invalid("stop deadline", "representable microseconds"))?;
    options.timeout = bound.remaining()?;
    let original_key = input.idempotency_key.clone();
    let reply = BlockingIpcClient::stop(
        endpoint,
        &super::credential::require(files)?,
        input.idempotency_key,
        se_types::UnixMicros::new(deadline as u64)?,
        &options,
    )?;
    match reply.outcome {
        RuntimeStopOutcome::Refused { error } => Err(SeError {
            body: error.body().clone(),
            cause: None,
        }),
        RuntimeStopOutcome::Facts {
            mut achieved,
            retained_resume,
            mut pending,
        } => {
            // The fixed reply precedes native closure. A protected post-transport
            // record supplies per-lifecycle facts without changing stop/v1.
            let mut report = None;
            #[cfg(any(target_os = "linux", windows))]
            match completion::report(files, endpoint, &original_key, &bound) {
                Ok(value) => report = value,
                Err(error) => pending.push(format!(
                    "Post-transport shutdown facts remain unproved: {error}"
                )),
            }
            if let Some(report) = &report {
                for reason in &report.pending {
                    if !pending.contains(reason) {
                        pending.push(reason.clone());
                    }
                }
                if !report.resources_closed {
                    pending.push("The original stop's post-transport receipt does not prove complete runtime resource closure.".into());
                }
            }
            #[cfg(any(target_os = "linux", windows))]
            if pending.is_empty() {
                match completion::witness(files, endpoint, &original_key, &bound) {
                    Ok(()) => achieved.extend([Fact::ResourcesClosed, Fact::LeaseReleased]),
                    Err(error) => pending.push(format!(
                        "Final native resource/lease release remains unproved: {error}"
                    )),
                }
            }
            let observed_at = receipt::timestamp(execute::now_us()?)?;
            let retained_count = retained_resume.len();
            let stops = stops::render(report.as_ref(), retained_resume, &observed_at, &mut pending);
            let missing: Vec<_> = [
                Fact::AgentsStopped,
                Fact::ResumeSaved,
                Fact::CaptureFlushed,
                Fact::DebtFlushed,
                Fact::WriterJoined,
                Fact::ResourcesClosed,
                Fact::LeaseReleased,
            ]
            .into_iter()
            .filter(|fact| !achieved.contains(fact))
            .collect();
            if !missing.is_empty() {
                pending.push(format!("Shutdown did not report these required facts: {missing:?}. Their absence is not a successful stop; preserve this data home and inspect the named obligations."));
            }
            let complete = pending.is_empty() && stops.iter().all(|stop| stop.complete);
            let detail = format!(
                "Achieved: {achieved:?}; retained resume references: {retained_count}; pending: {}",
                pending.join("; ")
            );
            Ok(RuntimeStop {
                complete,
                stops,
                witness: Witness {
                    state: if complete {
                        WitnessState::Witnessed
                    } else {
                        WitnessState::Unknown
                    },
                    method: if complete {
                        "authenticated shutdown stages and outside native completion readback"
                    } else {
                        "authenticated shutdown stages with pending completion readback"
                    }
                    .into(),
                    observed_at: receipt::timestamp(execute::now_us()?)?,
                    detail: Some(detail),
                },
            }
            .into())
        }
    }
}
