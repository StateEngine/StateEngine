//! Recovery that a reboot may have decided: a lifecycle whose recorded boot has
//! ended is proven exited by the reboot itself, so no process is signalled, and
//! launch closes such a lifecycle before starting its successor. The launch
//! coordinator runs these decisions; this module never reads its state.
use crate::{LaunchCoordinator, client::lease::Deadline};
use se_core::ops::{agent_launch::LaunchPlan, process_commit};
use se_proc::{
    CheckpointKind, CheckpointSource, NativeProcessRuntime, ProcessRuntime, RecoveryOutcome,
    RecoverySource,
};
use se_store::{Actor, OwnerGuardProcess, ProcessState};
use se_types::Result;

fn error(subject: &str, cause: impl std::fmt::Debug) -> se_types::SeError {
    se_core::scope::unreadable(subject, &format!("{cause:?}"))
}

/// Prove that a reboot ended the retained lifecycle, keeping an exit witness
/// committed earlier, or else recover its native custody. Blocking; the caller
/// runs it on its worker pool.
pub(crate) fn recover(
    native: &NativeProcessRuntime,
    machine: se_types::MachineId,
    generation: se_types::HostGeneration,
    checkpoint: se_proc::Checkpoint,
    retained: &OwnerGuardProcess,
) -> Result<RecoveryOutcome> {
    let recorded_exit = match (retained.state, &checkpoint.checkpoint) {
        (ProcessState::Exited, CheckpointKind::Exit { witness, .. }) => Some(witness.clone()),
        _ => None,
    };
    let source = recovery_source(&checkpoint, retained)?;
    if let se_store::RecordedIdentity::Present(instance) = &retained.identity.instance {
        let current = se_proc::observe_reboot_boot(machine)
            .map_err(|e| error("native reboot identity", e))?;
        match se_proc::prove_reboot(&checkpoint, instance, &current) {
            se_proc::RebootProof::Proven(proof) => {
                if let Some(witness) = recorded_exit {
                    return Ok(RecoveryOutcome::Exited(Box::new(witness)));
                }
                let witness = native
                    .witness_reboot(&proof)
                    .map_err(|e| error("native reboot witness", e))?;
                return Ok(RecoveryOutcome::Exited(Box::new(witness)));
            }
            se_proc::RebootProof::NotProven => {}
            se_proc::RebootProof::Unreadable(reason) => return Err(error("reboot proof", reason)),
        }
    }
    let plan = native
        .plan_recovery(source)
        .map_err(|e| error("native recovery plan", e))?;
    native
        .recover(plan, generation)
        .map_err(|e| error("native custody recovery", e))
}

/// Before an unforced launch, close the target's lifecycles that a reboot
/// already ended and plan again, so the successor starts clean.
pub(crate) async fn after_reboot(
    coordinator: &LaunchCoordinator,
    plan: LaunchPlan,
    admission: &se_store::Admission,
    deadline: &Deadline,
) -> Result<LaunchPlan> {
    if plan.input.force_selection.is_some() || !finish_launch(coordinator, &plan, deadline).await? {
        return Ok(plan);
    }
    let mut next = coordinator
        .replan_launch(&plan, admission, deadline)
        .await?;
    next.prepare_replacement(&plan, None, false)?;
    Ok(next)
}

/// Close each of this launch target's lifecycles that a reboot already ended.
/// Returns whether any was closed.
async fn finish_launch(
    coordinator: &LaunchCoordinator,
    plan: &LaunchPlan,
    deadline: &Deadline,
) -> Result<bool> {
    let pending = !plan.control.processes.is_empty() || !plan.control.sessions.is_empty();
    let records = if plan.control.processes.is_empty() {
        match &plan.control.latest_process {
            se_types::Read::Present { value } => std::slice::from_ref(value),
            _ => &[],
        }
    } else {
        plan.control.processes.as_slice()
    };
    let mut closed = false;
    for record in records {
        closed |= coordinator
            .close_rebooted(plan, record, pending, deadline)
            .await?;
    }
    Ok(closed)
}

/// The reason recorded for an exit: a reboot names itself, otherwise `other`.
pub(crate) fn exit_reason(witness: &se_proc::StopWitness, other: &'static str) -> &'static str {
    if witness.ended_by_reboot() {
        process_commit::ENDED_BY_REBOOT
    } else {
        other
    }
}
fn recovery_source(
    checkpoint: &se_proc::Checkpoint,
    retained: &OwnerGuardProcess,
) -> Result<RecoverySource> {
    if checkpoint.lifecycle != retained.identity.record
        || checkpoint.session != retained.identity.session
        || !matches!((&checkpoint.principal, &retained.identity.principal), (se_proc::CheckpointPrincipal::Agent(a),Actor::Agent(b)) if a==b)
    {
        return Err(error(
            "startup custody codec",
            "principal/session/lifecycle differs from protected index",
        ));
    }
    Ok(match &checkpoint.checkpoint {
        CheckpointKind::Reservation(v) => RecoverySource::Reservation(Box::new(v.clone())),
        CheckpointKind::Scope(v) => RecoverySource::Prepared(Box::new(v.clone())),
        CheckpointKind::Root(v) => RecoverySource::RootPrepared(Box::new(v.clone())),
        CheckpointKind::Process(v) => RecoverySource::Record(Box::new(v.clone())),
        CheckpointKind::Exit { source, .. } => match source.as_ref() {
            CheckpointSource::Reservation(v) => RecoverySource::Reservation(Box::new(v.clone())),
            CheckpointSource::Scope(v) => RecoverySource::Prepared(Box::new(v.clone())),
            CheckpointSource::Root(v) => RecoverySource::RootPrepared(Box::new(v.clone())),
            CheckpointSource::Process(v) => RecoverySource::Record(Box::new(v.clone())),
        },
        _ => {
            return Err(error(
                "startup custody codec",
                "unsupported terminal or historical checkpoint",
            ));
        }
    })
}
