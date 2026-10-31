//! Explicit host control through the native bootstrap and authenticated fixed
//! stop protocol. No connection failure permits a direct-write fallback.
use super::{admit::Caller, execute, files::Files, process, status};
use crate::{bootstrap::Bootstrap, config::Origin};
use se_core::{ops::*, scope};
use se_host::client::{BlockingIpcClient, lease::Deadline};
use se_types::{Read, Result, SeError};
use std::num::NonZeroU32;

pub fn up(cx: &Bootstrap, files: &Files, caller: &Caller, _input: RuntimeUp) -> Result<AnyOutput> {
    if caller.owner.is_none() {
        return Err(SeError::invalid("runtime owner", "native owner authority"));
    }
    let options = execute::options();
    let bound = Deadline::from_options(&options)?;
    let endpoint = match execute::endpoint(files)? {
        Read::Present { value } => {
            BlockingIpcClient::connect_authenticated(
                &value,
                execute::credential(cx, files)?,
                NonZeroU32::new(se_host::client::wire::DEFAULT_REPLY_BYTES)
                    .ok_or_else(|| SeError::invalid("runtime reply budget", "positive"))?,
                &options,
            )?;
            value
        }
        Read::Absent { .. } => start(cx, files, &bound)?,
        _ => {
            return Err(scope::unreadable(
                "runtime endpoint",
                "a complete protected endpoint observation is required",
            ));
        }
    };
    Ok(RuntimeStart {
        state: "running".into(),
        process: process::observe(&endpoint, &bound)?,
        generation: endpoint.generation.get(),
        endpoint: status::endpoint_name(&endpoint)?,
    }
    .into())
}
#[cfg(any(target_os = "linux", windows))]
fn start(cx: &Bootstrap, files: &Files, bound: &Deadline) -> Result<se_host::EndpointRecord> {
    let configuration = match &cx.config.origin {
        Origin::File(path) => path.clone(),
        Origin::BuiltIn => cx.home.join("config.toml"),
    };
    let machine = super::identity::require_machine(files)?;
    match crate::runtime::host::start(&cx.home, &configuration, machine, bound) {
        Ok(started) => {
            let started: crate::runtime::host::StartedHost = started;
            Ok(started.endpoint)
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
fn start(_cx: &Bootstrap, _files: &Files, _bound: &Deadline) -> Result<se_host::EndpointRecord> {
    Err(scope::unreadable(
        "runtime startup",
        "detached host startup is unavailable on this platform",
    ))
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
    use se_host::client::endpoint::{RuntimeStopFact as Fact, RuntimeStopOutcome};
    let options = execute::options();
    let endpoint = scope::require_present(
        execute::endpoint(files)?,
        "a live authenticated runtime endpoint for graceful down",
    )?;
    let now = execute::now_us()?;
    let deadline = now
        .checked_add(
            i64::try_from(options.timeout.as_micros())
                .map_err(|_| SeError::invalid("stop deadline", "representable microseconds"))?,
        )
        .ok_or_else(|| SeError::invalid("stop deadline", "representable microseconds"))?;
    let reply = BlockingIpcClient::stop(
        &endpoint,
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
            achieved,
            retained_resume,
            pending,
        } => {
            let complete = pending.is_empty()
                && retained_resume.is_empty()
                && [
                    Fact::AgentsStopped,
                    Fact::ResumeSaved,
                    Fact::CaptureFlushed,
                    Fact::DebtFlushed,
                    Fact::WriterJoined,
                    Fact::ResourcesClosed,
                    Fact::LeaseReleased,
                ]
                .iter()
                .all(|fact| achieved.contains(fact));
            let detail = format!(
                "Achieved: {achieved:?}; retained resume references: {}; pending: {}",
                retained_resume.len(),
                pending.join("; ")
            );
            let observed_at = receipt::timestamp(execute::now_us()?)?;
            let stops = retained_resume.into_iter().map(|retained| StopFact {
                target: retained.agent.to_string(),
                complete: false,
                witness: Witness {
                    state: WitnessState::Unknown,
                    method: "authenticated retained resume reference".into(),
                    observed_at: observed_at.clone(),
                    detail: Some(format!("project={}; agent={}; conversation={}", retained.project, retained.agent, retained.conversation)),
                },
                resume: ResumeCommand {
                    ready: false,
                    mode: "unknown".into(),
                    reason: Some("The host retained this conversation reference; no provider resume command was witnessed.".into()),
                    command: None,
                    argv: None,
                },
            }).collect();
            Ok(RuntimeStop {
                complete,
                stops,
                witness: Witness {
                    state: if complete {
                        WitnessState::Witnessed
                    } else {
                        WitnessState::Unknown
                    },
                    method: "authenticated fixed graceful-stop reply".into(),
                    observed_at: receipt::timestamp(execute::now_us()?)?,
                    detail: Some(detail),
                },
            }
            .into())
        }
    }
}
