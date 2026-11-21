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
    caller: &admit::Caller,
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
    matches!(endpoint(files), Ok(Read::Present { .. }))
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

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn dispatch_with_cold_recovery(
    cx: &Bootstrap,
    op: AnyOp,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
    recover_cold: bool,
) -> Result<AnyOutput> {
    let observation_deadline = super::session_observation::deadline()?;
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
        return super::diagnostic_bundle::execute(cx, input);
    }
    if let AnyOp::ProjectInit(input) = op {
        return super::init::execute(cx, input);
    }
    if let AnyOp::StoreRestore(input) = op {
        return super::restore::execute(cx, input, diagnostic);
    }
    if let AnyOp::Uninstall(input) = op {
        return Ok(super::uninstall::execute(cx, input, diagnostic)?.into());
    }
    if matches!(op, AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_))
        && let Some(output) = super::doctor::permissions::recover(cx, &op, diagnostic)?
    {
        return Ok(output);
    }
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
    if matches!(op, AnyOp::ProjectStatus(_)) {
        // Ask the daemon concurrently with this process's own build. The local
        // build stays authoritative, so status is still honest when the daemon
        // is absent or stale; only the wall time changes, from the sum of the
        // two to the longer of them.
        let ask_daemon = uses_host_observation(cx, &files, &mut snapshot, &caller);
        // The request owns everything it needs, so it runs on an unscoped thread
        // and this frame never waits for it unless the answer is used below. A
        // local error, a removed project or `--all` therefore returns at once
        // instead of joining a daemon that is slow, paused or gone; the thread
        // prints nothing and holds no lock this path needs.
        let pending = ask_daemon.then(|| {
            daemon_observation_start(super::hosted::StatusRequest::prepare(
                cx,
                &files,
                &caller,
                &selections,
            ))
        });
        #[cfg(any(windows, target_os = "macos"))]
        let defer_git =
            pending.is_some() && matches!(&op, AnyOp::ProjectStatus(input) if !input.fresh);
        #[cfg(not(any(windows, target_os = "macos")))]
        let defer_git = false;
        let result = super::status::observe_snapshot_watched(
            cx,
            &mut snapshot,
            owner,
            &files,
            &caller.admission,
            None,
            defer_git,
        );
        #[cfg(any(windows, target_os = "macos"))]
        let early = early_status(&pending, &op, defer_git && result.is_ok());
        let result = result.and_then(|mut output| {
            #[cfg(any(windows, target_os = "macos"))]
            complete_deferred_status(cx, &files, &mut output, &early, defer_git);
            #[cfg(not(any(windows, target_os = "macos")))]
            let _ = &mut output;
            super::session_observation::prepare(
                output,
                &mut snapshot,
                &caller.admission,
                observation_deadline,
            )
        });
        let prepared = finish_read(result, snapshot.close().map_err(|e| store_error(&e)))?;
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
                    merge_status_pending(&mut status.value.pending, &live.value.pending, &op);
                    live.value.atlas.clone()
                }
                Ok(_) => se_core::ops::status::atlas_view(Err(scope::unreadable(
                    "Atlas status",
                    "the host returned a different operation family",
                ))),
                Err(error) => se_core::ops::status::atlas_view(Err(se_types::SeError::from(
                    error.body.clone(),
                ))),
            };
            service_observation = Some(observed);
        }
        if let Some(live) = service_observation {
            output = super::session_observation::merge_runtime_observation(output, live)?;
        }
        return super::status::finish(cx, &reader, output, &caller.admission);
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
            &selections,
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
            let live = match endpoint(&files) {
                Ok(Read::Present { .. }) => Some(super::hosted::forward(
                    cx,
                    &files,
                    &reader,
                    &caller,
                    observation_op,
                    &selections,
                    diagnostic,
                )),
                Ok(Read::Absent { .. }) => None,
                Ok(Read::Unreadable { source, reason, .. }) => {
                    Some(Err(scope::unreadable(&source, &reason)))
                }
                Ok(Read::Unknown { what }) => {
                    Some(Err(scope::unreadable("runtime endpoint", &what)))
                }
                Err(error) => Some(Err(error)),
            };
            if let Some(live) = live {
                output = super::session_observation::merge_runtime_observation(output, live)?;
            }
        }
        return super::status::finish(cx, &reader, output, &caller.admission);
    }
    let identity = snapshot
        .info()
        .direct_lease_identity(caller.admission.generation);
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
    if let AnyOp::ProjectMove(input) = &op {
        return super::project_move::execute(cx, &reader, &caller, input.clone());
    }
    if let AnyOp::RuntimeDown(input) = op {
        return super::runtime_control::down(cx, &files, &reader, input, recover_cold);
    }
    if host_required && !matches!(op, AnyOp::RuntimeUp(_)) {
        let retry = super::startup_retry::Retry::capture(cx, &caller.admission, &op);
        return super::hosted::forward(cx, &files, &reader, &caller, op, &selections, diagnostic)
            .map_err(|error| retry.attach(error));
    }
    reader.validate_identity().map_err(|e| store_error(&e))?;
    let lease = DirectLease::acquire(&files, &cx.home.join("runtime.lock"), identity)
        .map_err(|e| store_error(&e))?;
    let retry = super::startup_retry::Retry::capture(cx, &caller.admission, &op);
    if let AnyOp::RuntimeUp(input) = op {
        // Activation requires the host's exclusive lease, so the direct shared
        // lease must be gone before spawning or rendezvousing with it.
        drop(lease);
        return super::runtime_control::up(cx, &files, &caller, input, diagnostic)
            .map_err(|error| retry.attach(error));
    }
    let Some(lease) = lease else {
        let target = scope::require_present(
            endpoint(&files)?,
            "live runtime endpoint while the writer lease is busy",
            "Wait for the current runtime to publish its endpoint, then retry with the original --key; do not remove runtime.lock or bypass its holder.",
        )?;
        let forwarding = forwarding_options(cx, &files, &target)?;
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
fn finish_read<T>(result: Result<T>, closed: Result<()>) -> Result<T> {
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
                    se_core::ports::CustodyPlan::AtlasAugment(_) => {
                        "host Atlas augmentation reader"
                    }
                    se_core::ports::CustodyPlan::AtlasRead(_) => "host Atlas reader",
                    se_core::ports::CustodyPlan::ClaudeHook(_) => "hook",
                    se_core::ports::CustodyPlan::Initialize(_) => "init",
                    #[cfg(feature = "import")]
                    se_core::ports::CustodyPlan::ImportNode(_) => "host history importer",
                    se_core::ports::CustodyPlan::ObserveStatus(_) => "status",
                    se_core::ports::CustodyPlan::RuntimeUp(_) => "runtime.up",
                    se_core::ports::CustodyPlan::RuntimeDown(_) => "runtime.down",
                    se_core::ports::CustodyPlan::Uninstall(_) => "uninstall",
                    se_core::ports::CustodyPlan::Launch(_) => "host launch coordinator",
                    se_core::ports::CustodyPlan::Stop(_) => "host stop coordinator",
                    se_core::ports::CustodyPlan::AgentWake(_) => "host wake coordinator",
                    se_core::ports::CustodyPlan::Remove(_) => "host removal coordinator",
                    se_core::ports::CustodyPlan::Forget(_) => "host erasure coordinator",
                }
                .into(),
            },
        ))),
    }
}
