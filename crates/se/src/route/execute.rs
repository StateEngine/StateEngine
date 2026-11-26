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
use se_store::{DirectStore, Snapshot, SqliteFactory, StateFiles, StoreFactory, StoreOptions};
use se_types::{AgentId, EventId, MessageId, Read, Result, SeError, Secret};
use std::{
    io::Read as _,
    ops::ControlFlow,
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
    let mut notification_event = [0; 10];
    let mut notification_message = [0; 10];
    notification_event.copy_from_slice(&random.expose()[20..30]);
    notification_message.copy_from_slice(&agent_random.expose()[20..30]);
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
        notification_event: EventId::from_parts(now as u64 / 1000, notification_event)?,
        notification_message: MessageId::from_parts(now as u64 / 1000, notification_message)?,
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
    cx: &Bootstrap,
    files: &Files,
    endpoint: &se_host::EndpointRecord,
) -> Result<ClientOptions> {
    let mut options = options();
    let started = std::time::Instant::now();
    let bound = se_host::client::lease::Deadline::from_options(&options)?;
    se_proc::native_ipc::restore_image_hint(
        &files.0,
        endpoint.image_sha256,
        cx.session.is_none().then_some(&endpoint.epoch.owner),
        &bound.native_bound(),
    )
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
            Ok(Read::Present {
                value: super::endpoint_diagnostic::decode(files.0.root(), &bytes)?,
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
    dispatch_with_cold_recovery(cx, op, diagnostic, true)
}

/// Removal may stop a live host, but retained cold custody requires an explicit
/// down first. Keep ordinary admission and its non-mutating refusal intact.
pub(crate) fn stop_for_uninstall(
    cx: &Bootstrap,
    input: se_core::ops::RuntimeDown,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    dispatch_with_cold_recovery(cx, AnyOp::RuntimeDown(input), diagnostic, false)
}

/// The admitted caller and store handles every store-backed route shares.
#[derive(Clone, Copy)]
pub(super) struct RouteContext<'a> {
    pub(super) cx: &'a Bootstrap,
    pub(super) files: &'a Files,
    pub(super) reader: &'a se_store::SqliteReader,
    pub(super) caller: &'a super::admit::Caller,
    pub(super) selections: &'a se_core::ops::CliSelections,
    pub(super) observation_deadline: std::time::Instant,
}

fn dispatch_with_cold_recovery(
    cx: &Bootstrap,
    op: AnyOp,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
    recover_cold: bool,
) -> Result<AnyOutput> {
    let observation_deadline = super::session_observation::deadline()?;
    let op = match route_without_store(cx, op, diagnostic)? {
        ControlFlow::Break(output) => return Ok(output),
        ControlFlow::Continue(op) => op,
    };
    let (files, (reader, mut phase)) =
        match setup::inspect_short(&cx.home, se_core::ops::receipt::timestamp(now_us()?)?)? {
            setup::Setup::Absent(output) if matches!(op, AnyOp::ProjectStatus(_)) => {
                return Ok((*output).into());
            }
            setup::Setup::Absent(_)
                if matches!(op, AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_)) =>
            {
                return super::doctor::uninitialized(cx, &op);
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
    let mut caller = admit::observe(cx, &mut phase, &files)?;
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
    let ctx = RouteContext {
        cx,
        files: &files,
        reader: &reader,
        caller: &caller,
        selections: &selections,
        observation_deadline,
    };
    if matches!(op, AnyOp::ProjectStatus(_)) {
        return super::status_dispatch::dispatch(ctx, &op, snapshot, owner);
    }
    if matches!(op, AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_)) {
        snapshot.close().map_err(|e| store_error(&e))?;
        return super::doctor::execute(cx, &files, &reader, &caller, op, diagnostic);
    }
    let host_required = matches!(
        op.meta().runtime,
        RuntimeNeed::Host | RuntimeNeed::HostAutoStart
    );
    if op.meta().effect == Effect::Read && !host_required {
        return dispatch_read(ctx, op, snapshot, diagnostic);
    }
    let identity = snapshot
        .info()
        .direct_lease_identity(caller.admission.generation);
    // End the finite auth/selection pin before stdin, IPC, writer or custody work.
    snapshot.close().map_err(|e| store_error(&e))?;
    dispatch_write(ctx, op, identity, host_required, recover_cold, diagnostic)
}

/// Routes that answer before the store is opened: setup, recovery and
/// uninstall paths, and a Node import path made absolute.
fn route_without_store(
    cx: &Bootstrap,
    op: AnyOp,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<ControlFlow<AnyOutput, AnyOp>> {
    #[cfg(feature = "import")]
    let op = {
        let mut op = op;
        if let AnyOp::ImportNode(input) = &mut op {
            let path = std::path::PathBuf::from(&input.from_node);
            let absolute = if path.is_absolute() {
                path
            } else {
                cx.cwd.join(path)
            };
            input.from_node = absolute
                .to_str()
                .ok_or_else(|| {
                    SeError::invalid(
                        "Node source path",
                        "an exact UTF-8 CLI path; lossy path conversion is refused",
                    )
                })?
                .into();
        }
        op
    };
    if let AnyOp::DiagnosticBundle(input) = op {
        return super::diagnostic_bundle::execute(cx, input).map(ControlFlow::Break);
    }
    if let AnyOp::ProjectInit(input) = op {
        return super::init::execute(cx, input).map(ControlFlow::Break);
    }
    if let AnyOp::HarnessAdd(input) = op {
        return super::harness_setup::add(cx, input).map(ControlFlow::Break);
    }
    if let AnyOp::StoreRestore(input) = op {
        return super::restore::execute(cx, input, diagnostic).map(ControlFlow::Break);
    }
    if let AnyOp::Uninstall(input) = op {
        return Ok(ControlFlow::Break(
            super::uninstall::execute(cx, input, diagnostic)?.into(),
        ));
    }
    if let AnyOp::WorktreeRemove(input) = op {
        return crate::repository::worktree::remove(cx, input).map(ControlFlow::Break);
    }
    if matches!(op, AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_))
        && let Some(output) = super::doctor::permissions::recover(cx, &op, diagnostic)?
    {
        return Ok(ControlFlow::Break(output));
    }
    Ok(ControlFlow::Continue(op))
}

/// A read that needs no host: plan it on the finite snapshot, then merge a
/// live runtime observation when the output asks for one.
fn dispatch_read(
    ctx: RouteContext<'_>,
    op: AnyOp,
    snapshot: se_store::SqliteSnapshot,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    let mut op = op;
    let mut snapshot = match hosted_resume(ctx, &mut op, snapshot, diagnostic)? {
        Resumed::Hosted(hosted) => {
            return super::status::finish(ctx.cx, ctx.reader, hosted, &ctx.caller.admission);
        }
        Resumed::Local(snapshot) => *snapshot,
    };
    let RouteContext {
        cx,
        files,
        reader,
        caller,
        selections,
        observation_deadline,
    } = ctx;
    let observation_op = op.clone();
    let observed = se_types::UnixMicros::new(u64::try_from(now_us()?).map_err(|_| {
        SeError::invalid("read observation clock", "nonnegative Unix microseconds")
    })?)?;
    let read_kernel = Kernel::read_only_at(observed)
        .with_command_home(&cx.home)
        .with_configuration(cx.config.value.clone())?
        .with_config_origin(cx.config.origin.label());
    let result = direct::plan_snapshot(
        &mut snapshot,
        &caller.admission,
        &caller.terminal,
        &read_kernel,
        op,
        selections,
    )
    .and_then(|step| match step {
        se_core::commit::OpStep::Complete(output) => Ok(output),
        _ => Err(SeError::invalid(
            "direct read plan",
            "a read without commit or custody",
        )),
    })
    .and_then(|output| {
        super::session_observation::prepare(
            output,
            &mut snapshot,
            &caller.admission,
            observation_deadline,
        )
    });
    let prepared = finish_read(result, snapshot.close().map_err(|e| store_error(&e)))?;
    let mut output = super::session_observation::finish(prepared, &cx.home)?;
    if super::session_observation::has_runtime_observation(&output) {
        let live = match endpoint(files) {
            Ok(Read::Present { .. }) => Some(super::hosted::forward(
                cx,
                files,
                reader,
                caller,
                observation_op,
                selections,
                diagnostic,
            )),
            Ok(Read::Absent { .. }) => None,
            Ok(Read::Unreadable { source, reason, .. }) => {
                Some(Err(scope::unreadable(&source, &reason)))
            }
            Ok(Read::Unknown { what }) => Some(Err(scope::unreadable("runtime endpoint", &what))),
            Err(error) => Some(Err(error)),
        };
        if let Some(live) = live {
            output = super::session_observation::merge_runtime_observation(output, live)?;
        }
    }
    super::status::finish(cx, reader, output, &caller.admission)
}

/// Who answers a resume: the running host, or this process from the store.
enum Resumed {
    Hosted(AnyOutput),
    Local(Box<se_store::SqliteSnapshot>),
}

/// An agent session's resume is answered by its running host, which adds code
/// context and orientation. The admission snapshot closes before the host is
/// asked, so no read stays open across that wait. With no host the store-only
/// answer stands; a host that fails to answer, or whose endpoint cannot be
/// read, becomes a source failure the store-only packet fits in its budget.
fn hosted_resume(
    ctx: RouteContext<'_>,
    op: &mut AnyOp,
    snapshot: se_store::SqliteSnapshot,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<Resumed> {
    let RouteContext {
        cx,
        files,
        reader,
        caller,
        selections,
        ..
    } = ctx;
    let AnyOp::Resume(input) = op else {
        return Ok(Resumed::Local(Box::new(snapshot)));
    };
    if !matches!(caller.admission.actor, se_store::Actor::Agent(_))
        || caller.admission.session.is_none()
    {
        return Ok(Resumed::Local(Box::new(snapshot)));
    }
    let (failure, snapshot) = match endpoint(files) {
        Ok(Read::Absent { .. }) => return Ok(Resumed::Local(Box::new(snapshot))),
        Ok(Read::Present { .. }) => {
            snapshot.close().map_err(|e| store_error(&e))?;
            let forwarded = AnyOp::Resume(input.clone());
            let failure = match super::hosted::forward(
                cx, files, reader, caller, forwarded, selections, diagnostic,
            ) {
                Ok(hosted @ AnyOutput::Resume(_)) => return Ok(Resumed::Hosted(hosted)),
                Ok(_) => {
                    scope::unreadable("hosted resume", "the host answered with another output")
                }
                Err(error) => error,
            };
            (failure, fallback_snapshot(ctx, op)?)
        }
        Ok(Read::Unreadable { source, reason, .. }) => {
            (scope::unreadable(&source, &reason), snapshot)
        }
        Ok(Read::Unknown { what }) => (scope::unreadable("runtime endpoint", &what), snapshot),
        Err(error) => (error, snapshot),
    };
    if let AnyOp::Resume(input) = op {
        input.source_failure = Some(
            scope::unreadable(
                "code context and orientation from the running host",
                &failure.body.message(),
            )
            .into_body(),
        );
    }
    Ok(Resumed::Local(Box::new(snapshot)))
}

/// A fresh snapshot for the store-only resume, selected as admission was.
fn fallback_snapshot(ctx: RouteContext<'_>, op: &AnyOp) -> Result<se_store::SqliteSnapshot> {
    let admission = &ctx.caller.admission;
    let mut snapshot =
        se_store::ReadStore::snapshot(ctx.reader, se_core::admission::read_scope(admission))
            .map_err(|e| store_error(&e))?;
    super::select::apply(ctx.cx, &mut snapshot, &mut admission.clone(), op)?;
    if let se_store::Scope::Project(project) = &admission.scope {
        snapshot
            .select_project(project.clone())
            .map_err(|e| store_error(&e))?;
    }
    Ok(snapshot)
}

/// Writes and host operations: authorize, then forward to the host or take
/// the direct writer lease.
fn dispatch_write(
    ctx: RouteContext<'_>,
    op: AnyOp,
    identity: se_store::LeaseIdentity,
    host_required: bool,
    recover_cold: bool,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    let RouteContext {
        cx,
        files,
        reader,
        caller,
        selections,
        ..
    } = ctx;
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
        && let Some(absent) = super::remove::absent(cx, files, reader, &caller.admission, input)?
    {
        return Ok(absent);
    }
    if let AnyOp::ProjectMove(input) = &op {
        return super::project_move::execute(cx, reader, caller, input.clone());
    }
    if let AnyOp::RuntimeDown(input) = op {
        return super::runtime_control::down(cx, files, reader, input, recover_cold);
    }
    if host_required && !matches!(op, AnyOp::RuntimeUp(_)) {
        let retry = super::startup_retry::Retry::capture(cx, &caller.admission, &op);
        return super::hosted::forward(cx, files, reader, caller, op, selections, diagnostic)
            .map_err(|error| retry.attach(error));
    }
    reader.validate_identity().map_err(|e| store_error(&e))?;
    let lease = DirectLease::acquire(files, &cx.home.join("runtime.lock"), identity)
        .map_err(|e| store_error(&e))?;
    let retry = super::startup_retry::Retry::capture(cx, &caller.admission, &op);
    if let AnyOp::RuntimeUp(input) = op {
        // Activation requires the host's exclusive lease, so the direct shared
        // lease must be gone before spawning or rendezvousing with it.
        drop(lease);
        return super::runtime_control::up(cx, files, caller, input, diagnostic)
            .map_err(|error| retry.attach(error));
    }
    let Some(lease) = lease else {
        let target = scope::require_present(
            endpoint(files)?,
            "live runtime endpoint while the writer lease is busy",
            "Wait for the current runtime to publish its endpoint, then retry with the original --key; do not remove runtime.lock or bypass its holder.",
        )?;
        let forwarding = forwarding_options(cx, files, &target)?;
        return crate::ipc::forward(
            &target,
            credential(cx, files)?,
            op,
            selections,
            caller
                .owner
                .as_ref()
                .map(|owner| owner.native_observation()),
            &forwarding,
        );
    };
    execute_direct(ctx, op, lease)
}

/// Execute under the direct writer lease, naming a committed operation when
/// the store close fails after COMMIT.
fn execute_direct(
    ctx: RouteContext<'_>,
    op: AnyOp,
    lease: DirectLease<&Files>,
) -> Result<AnyOutput> {
    let RouteContext {
        cx,
        caller,
        selections,
        ..
    } = ctx;
    let store_options = StoreOptions {
        state_directory: cx.home.clone(),
        busy_timeout: Duration::from_millis(250),
    };
    let mut store = scope::require_present(
        SqliteFactory::open_direct(&store_options, &lease).map_err(|e| store_error(&e))?,
        "initialized direct store",
        "Restore access to the initialized store in this same data home before retrying with the original --key; do not recreate or replace the store.",
    )?;
    let kernel = Kernel::new(facts()?)?
        .with_configuration(cx.config.value.clone())?
        .with_config_origin(cx.config.origin.label());
    let operation_name = op.meta().name;
    let result = direct::execute(
        &mut store,
        &lease,
        &caller.admission,
        &caller.terminal,
        &kernel,
        op,
        selections,
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
            outcome.into_output()
        }
        Err(error) => Err(match closed {
            Ok(()) => error,
            Err(close) => error.with_cause(close),
        }),
    }
}

pub(super) fn finish_read<T>(result: Result<T>, closed: Result<()>) -> Result<T> {
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
