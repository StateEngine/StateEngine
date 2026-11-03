//! Concrete public CLI routing. Only a held native shared lease admits direct
//! writes; a busy lease selects authenticated host forwarding, never fallback.
use super::{
    admit, direct,
    files::{DirectLease, Files},
    select, setup,
};
use crate::bootstrap::Bootstrap;
use se_core::{
    dispatch::{CallFacts, Kernel},
    ops::{AnyOp, AnyOutput},
    registry::{Effect, RuntimeNeed},
    scope,
    store_error::store_error,
};
use se_host::client::{ClientOptions, lease::ClientCredential};
use se_store::{
    DirectStore, LeaseIdentity, LeaseMode, ReadStore, Snapshot, SqliteFactory, StateFiles,
    StoreFactory, StoreOptions,
};
use se_types::{AgentId, EventId, MessageId, Read, Result, SeError, Secret};
use std::{
    io::Read as _,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub use super::clock::now_us;
pub fn facts() -> Result<CallFacts> {
    let now = now_us()?;
    let random = se_proc::random_secret()
        .map_err(|e| scope::unreadable("operation identity allocation", &e.to_string()))?;
    let agent_random = se_proc::random_secret()
        .map_err(|e| scope::unreadable("agent identity allocation", &e.to_string()))?;
    let mut event = [0; 10];
    let mut message = [0; 10];
    let mut agent = [0; 10];
    let mut profile_event = [0; 10];
    event.copy_from_slice(&random.expose()[..10]);
    message.copy_from_slice(&random.expose()[10..20]);
    agent.copy_from_slice(&agent_random.expose()[..10]);
    profile_event.copy_from_slice(&agent_random.expose()[10..20]);
    Ok(CallFacts {
        event: EventId::from_parts(now as u64 / 1000, event)?,
        message: MessageId::from_parts(now as u64 / 1000, message)?,
        agent: AgentId::from_parts(now as u64 / 1000, agent)?,
        profile_event: EventId::from_parts(now as u64 / 1000, profile_event)?,
        occurred_at_us: now,
        door: se_store::Door::Cli,
    })
}
pub fn options() -> ClientOptions {
    ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn forwarding_options(
    home: &std::path::Path,
    endpoint: &se_host::EndpointRecord,
) -> Result<ClientOptions> {
    let mut options = options();
    let started = std::time::Instant::now();
    let bound = se_host::client::lease::Deadline::from_options(&options)?;
    se_proc::native_ipc::restore_image_cache(home, endpoint.image_sha256, &bound.native_bound())
        .map_err(|error| scope::unreadable("protected executable cache", &error.to_string()))?;
    options.timeout = options.timeout.saturating_sub(started.elapsed());
    Ok(options)
}
pub fn endpoint(files: &Files) -> Result<Read<se_host::EndpointRecord>> {
    let path = files.0.root().join("endpoint.json");
    match files.readback(&path).map_err(|e| store_error(&e))? {
        Read::Present { value: file } => {
            let mut bytes = Vec::new();
            let max = se_host::client::wire::MAX_ENDPOINT_BYTES;
            file.take(max as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| scope::unreadable("protected runtime endpoint", &e.to_string()))?;
            if bytes.len() > max {
                return Err(SeError::too_large("endpoint", max, bytes.len()));
            }
            Ok(Read::Present {
                value: se_host::client::endpoint::decode_endpoint(&bytes)?,
            })
        }
        Read::Absent { checked } => Ok(Read::Absent { checked }),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => Err(scope::unreadable("runtime endpoint", &what)),
    }
}
pub fn credential(cx: &Bootstrap, files: &Files) -> Result<ClientCredential> {
    match &cx.session {
        Some(secret) => Ok(ClientCredential::Session(Secret::new(
            secret.expose().to_vec(),
        )?)),
        None => Ok(ClientCredential::Machine(super::credential::require(
            files,
        )?)),
    }
}
pub fn dispatch(
    cx: &Bootstrap,
    op: AnyOp,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    if let AnyOp::ProjectInit(input) = op {
        return super::init::execute(cx, input);
    }
    if let AnyOp::Uninstall(input) = op {
        return Ok(super::uninstall::execute(cx, input, diagnostic)?.into());
    }
    if matches!(op, AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_))
        && let Some(output) = super::doctor::permissions::recover(cx, &op, diagnostic)?
    {
        return Ok(output);
    }
    let (files, (reader, phase)) =
        match setup::inspect_phase(&cx.home, se_core::ops::receipt::timestamp(now_us()?)?)? {
            setup::Setup::Absent(output) if matches!(op, AnyOp::ProjectStatus(_)) => {
                return Ok((*output).into());
            }
            setup::Setup::Absent(_) => {
                return Err(setup::required(cx));
            }
            setup::Setup::Present(reader) => reader,
        };
    // The host verifier admits a prepared launch's first fixed hook after C3.
    // End this finite read pin before stdin or forwarding; ordinary operations
    // still require active-session admission below.
    if let AnyOp::HookClaude(hook) = &op {
        admit::hook_session(cx, phase)?;
        drop(reader);
        let input = crate::hook::read_native(hook.event, &mut std::io::stdin().lock())?;
        return super::hook::forward(cx, &files, input, diagnostic);
    }
    let owner = if matches!(op, AnyOp::ProjectStatus(_)) {
        Some(phase.runtime_owner().map_err(|e| store_error(&e))?)
    } else {
        None
    };
    let mut caller = admit::observe(cx, &phase, &files)?;
    let mut snapshot = phase
        .into_snapshot(se_core::admission::read_scope(&caller.admission))
        .map_err(|e| store_error(&e))?;
    select::apply(cx, &mut snapshot, &mut caller.admission, &op)?;
    if let se_store::Scope::Project(project) = &caller.admission.scope {
        snapshot
            .select_project(project.clone())
            .map_err(|e| store_error(&e))?;
    }
    let mut selections = cx.selections.clone();
    if let se_store::Scope::Project(project) = &caller.admission.scope {
        selections.project = Some(project.clone());
    }
    if matches!(op, AnyOp::ProjectStatus(_)) {
        let result =
            super::status::observe_snapshot(cx, &mut snapshot, owner, &files, &caller.admission);
        return finish_read(result, snapshot.close().map_err(|e| store_error(&e)));
    }
    if matches!(op, AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_)) {
        snapshot.close().map_err(|e| store_error(&e))?;
        return super::doctor::execute(cx, &files, &caller, op, diagnostic);
    }
    let host_required = matches!(
        op.meta().runtime,
        RuntimeNeed::Host | RuntimeNeed::HostAutoStart
    );
    if op.meta().effect == Effect::Read && !host_required {
        let observed = se_types::UnixMicros::new(u64::try_from(now_us()?).map_err(|_| {
            SeError::invalid("read observation clock", "nonnegative Unix microseconds")
        })?)?;
        let result = direct::plan_snapshot(
            &mut snapshot,
            &caller.admission,
            &caller.terminal,
            &Kernel::read_only_at(observed),
            op,
            &selections,
        )
        .and_then(|step| match step {
            se_core::commit::OpStep::Complete(output) => Ok(output),
            _ => Err(SeError::invalid(
                "direct read plan",
                "a read without commit or custody",
            )),
        });
        return finish_read(result, snapshot.close().map_err(|e| store_error(&e)));
    }
    // End the finite auth/selection pin before stdin, IPC, writer or custody work.
    snapshot.close().map_err(|e| store_error(&e))?;
    se_core::admission::authorize(op.meta(), &caller.admission)?;
    // Refuse before acquiring writer custody or looking for a busy host's
    // endpoint; Kernel::plan still enforces policy for every execution path.
    if op.requires_human_terminal()? {
        se_core::admission::require_human_terminal(
            op.meta().name,
            &caller.admission,
            &caller.terminal,
        )?;
    }
    if let AnyOp::ProjectRemove(input) = &op
        && let Some(absent) = super::remove::absent(cx, &files, &reader, &caller.admission, input)?
    {
        return Ok(absent);
    }
    if let AnyOp::RuntimeDown(input) = op {
        return super::runtime_control::down(&files, input);
    }
    if host_required && !matches!(op, AnyOp::RuntimeUp(_)) {
        return super::hosted::forward(cx, &files, &reader, &caller, op, &selections, diagnostic);
    }
    let identity = LeaseIdentity {
        store: Some(reader.info().map_err(|e| store_error(&e))?.id),
        generation: caller.admission.generation,
        mode: LeaseMode::DirectClient,
    };
    let lease = DirectLease::acquire(
        Files::open(&cx.home).map_err(|e| store_error(&e))?,
        &cx.home.join("runtime.lock"),
        identity,
    )
    .map_err(|e| store_error(&e))?;
    if let AnyOp::RuntimeUp(input) = op {
        // Activation requires the host's exclusive lease, so the direct shared
        // lease must be gone before spawning or rendezvousing with it.
        drop(lease);
        return super::runtime_control::up(cx, &files, &caller, input, diagnostic);
    }
    let Some(lease) = lease else {
        let target = scope::require_present(
            endpoint(&files)?,
            "live runtime endpoint while the writer lease is busy",
            "Wait for the current runtime to publish its endpoint, then retry with the original --key; do not remove runtime.lock or bypass its holder.",
        )?;
        let forwarding = forwarding_options(&cx.home, &target)?;
        return crate::ipc::forward(
            &target,
            credential(cx, &files)?,
            op,
            &selections,
            caller
                .owner
                .as_ref()
                .map(|owner| owner.native_observation()),
            &forwarding,
        );
    };
    let store_options = StoreOptions {
        state_directory: cx.home.clone(),
        busy_timeout: Duration::from_millis(250),
    };
    let mut store = scope::require_present(
        SqliteFactory::open_direct(&store_options, &lease).map_err(|e| store_error(&e))?,
        "initialized direct store",
        "Restore access to the initialized store in this same data home before retrying with the original --key; do not recreate or replace the store.",
    )?;
    let kernel = Kernel::new(facts()?)?.with_configuration(cx.config.value.clone())?;
    let operation_name = op.meta().name;
    let result = direct::execute(
        &mut store,
        &lease,
        &caller.admission,
        &caller.terminal,
        &kernel,
        op,
        &selections,
    );
    let closed = store.close().map_err(|e| store_error(&e));
    match result {
        Ok(outcome) => {
            if let Err(error) = closed {
                return Err(match &outcome {
                    direct::Outcome::Committed {
                        key,
                        natural_events,
                        events,
                        ..
                    } => direct::committed_failure(
                        operation_name,
                        key.as_ref(),
                        natural_events,
                        events,
                        error,
                    ),
                    _ => error,
                });
            }
            complete(outcome)
        }
        Err(error) => Err(match closed {
            Ok(()) => error,
            Err(close) => error.with_cause(close),
        }),
    }
}
fn finish_read(result: Result<AnyOutput>, closed: Result<()>) -> Result<AnyOutput> {
    match result {
        Ok(value) => {
            closed?;
            Ok(value)
        }
        Err(error) => Err(match closed {
            Ok(()) => error,
            Err(close) => error.with_cause(close),
        }),
    }
}

fn complete(outcome: direct::Outcome) -> Result<AnyOutput> {
    match outcome {
        direct::Outcome::Complete(output) | direct::Outcome::Committed { output, .. } => Ok(output),
        direct::Outcome::Custody(plan) => Err(SeError::new(se_types::Detail::Internal(
            se_types::details::Internal {
                report_id: "unrouted-cli-custody".into(),
                location: match plan {
                    se_core::ports::CustodyPlan::ClaudeHook(_) => "hook",
                    se_core::ports::CustodyPlan::Initialize(_) => "init",
                    se_core::ports::CustodyPlan::ObserveStatus(_) => "status",
                    se_core::ports::CustodyPlan::RuntimeUp(_) => "runtime.up",
                    se_core::ports::CustodyPlan::RuntimeDown(_) => "runtime.down",
                    se_core::ports::CustodyPlan::Uninstall(_) => "uninstall",
                    se_core::ports::CustodyPlan::Launch(_) => "host launch coordinator",
                    se_core::ports::CustodyPlan::Stop(_) => "host stop coordinator",
                    se_core::ports::CustodyPlan::Remove(_) => "host removal coordinator",
                }
                .into(),
            },
        ))),
    }
}
