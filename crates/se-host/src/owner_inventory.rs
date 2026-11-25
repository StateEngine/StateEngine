//! Join the one native checkpoint codec to protected store indices. This adapter
//! neither deserializes a second format nor reconstructs native handles.
use se_proc::{
    CheckpointKind, CheckpointPrincipal, CheckpointSource, LifecycleState, ProcessRecord,
    RootPublication,
};
use se_store::{
    Actor, ContainmentFact, OwnerGuardInventory, ProcessState, RecordedIdentity, RootIdentityState,
};
use se_types::Result;

pub fn decode_owner_inventory(inventory: &OwnerGuardInventory) -> Result<Vec<ProcessRecord>> {
    let mut records = Vec::with_capacity(inventory.processes.len());
    for entry in &inventory.processes {
        let identity = &entry.identity;
        let checkpoint =
            se_proc::decode_checkpoint(identity.custody.format_version, &identity.custody.record)
                .map_err(|error| unreadable(&error.to_string()))?;
        verify_checkpoint_header(&checkpoint, identity)?;
        if check_pending_owner(&checkpoint, entry.state, identity)? {
            continue;
        }
        #[cfg(windows)]
        if check_windows_prepared_job(&checkpoint, entry.state, identity)? {
            continue;
        }
        let (record, terminal_cleanup) = resolve_guard_record(&checkpoint, entry.state)?;
        if (!terminal_cleanup && !state_matches(record.state, entry.state))
            || record.ownership_release.is_some()
        {
            return Err(unreadable(
                "checkpoint state/release differs from the protected unresolved process index",
            ));
        }
        verify_recorded_root(record, identity)?;
        // BootId is an opaque display/transport label, with no native encoding
        // contract. The decoded native boot/start pair is validated by the codec
        // and checked against the kernel by observe_owner; it is never replaced
        // by that label or by PID-only discovery here.
        records.push(record.clone());
    }
    Ok(records)
}
fn verify_checkpoint_header(
    checkpoint: &se_proc::Checkpoint,
    identity: &se_store::ProcessIdentityRecord,
) -> Result<()> {
    let principal_matches = match (&checkpoint.principal, &identity.principal) {
        (CheckpointPrincipal::Agent(a), Actor::Agent(b)) => a == b,
        (CheckpointPrincipal::Human(a), Actor::Human(b)) => a == b,
        _ => false,
    };
    let root_matches = matches!(
        (&checkpoint.root_identity, &identity.root_identity),
        (
            RootPublication::NoChildCreated,
            RootIdentityState::NoChildCreated
        ) | (RootPublication::Unpublished, RootIdentityState::Unpublished)
            | (RootPublication::Identified, RootIdentityState::Identified)
            | (RootPublication::Unknown, RootIdentityState::Unknown)
    );
    if checkpoint.lifecycle != identity.record
        || checkpoint.session != identity.session
        || !principal_matches
        || !root_matches
    {
        return Err(unreadable(
            "checkpoint lifecycle/principal/session/root publication differs from the protected process index",
        ));
    }
    Ok(())
}
fn check_pending_owner(
    checkpoint: &se_proc::Checkpoint,
    state: ProcessState,
    identity: &se_store::ProcessIdentityRecord,
) -> Result<bool> {
    let pending_owner = match &checkpoint.checkpoint {
        CheckpointKind::Reservation(value) => Some(&value.owner),
        CheckpointKind::Scope(value) => Some(&value.reservation.owner),
        CheckpointKind::Root(value) => Some(&value.scope.reservation.owner),
        _ => None,
    };
    let Some(owner) = pending_owner else {
        return Ok(false);
    };
    let observed = se_proc::read_process(owner.machine.clone(), owner.pid)
        .map_err(|error| unreadable(&format!("{error:?}")))?;
    if matches!(&observed, se_proc::ProcessRead::Present(value)
        if value.identity == *owner
            && matches!(value.state, se_proc::NativeState::Running | se_proc::NativeState::Stopped))
    {
        return Err(se_types::ErrorBody::new(se_types::Detail::StateConflict(
            se_types::details::StateConflict {
                subject: "native launch custody".into(),
                reason: "The original host is still alive and launch custody has not finished publication or retirement; owner admission remains withheld.".into(),
                next_step: "Wait one second, then retry the same command with its original request key. If this persists, inspect the original host; do not delete custody records.".into(),
            },
        ))
        .with_retry(se_types::Retry::After(std::time::Duration::from_secs(1)))
        .into());
    }
    let owner_gone = match &observed {
        se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. } => true,
        se_proc::ProcessRead::Present(value) => {
            value.identity != *owner
                || matches!(
                    value.state,
                    se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                )
        }
    };
    // C1 precedes child publication. Once its exact owner is gone,
    // this reservation contributes no root to caller ancestry.
    // Keep the protected checkpoint intact: startup must still
    // reconcile native custody and commit its own exit witness.
    // A different native birth or executable is not the original
    // owner. This grants no signal rights over that successor;
    // scope/root custody and unreadable observations still refuse.
    Ok(owner_gone
        && matches!(checkpoint.checkpoint, CheckpointKind::Reservation(_))
        && state == ProcessState::Reserved
        && matches!(identity.instance, RecordedIdentity::Absent { .. })
        && matches!(identity.containment, ContainmentFact::NotLaunched))
}
#[cfg(windows)]
fn check_windows_prepared_job(
    checkpoint: &se_proc::Checkpoint,
    state: ProcessState,
    identity: &se_store::ProcessIdentityRecord,
) -> Result<bool> {
    let prepared = match (&checkpoint.checkpoint, state) {
        (CheckpointKind::Scope(prepared), ProcessState::Starting) => Some(prepared),
        // A second crash can interrupt credential/file cleanup after
        // native exit was committed. Re-probe the original job rather
        // than treating its terminal witness as a current observation.
        (CheckpointKind::Exit { source, .. }, ProcessState::Exited) => match source.as_ref() {
            CheckpointSource::Scope(prepared) => Some(prepared),
            _ => None,
        },
        _ => None,
    };
    if let Some(prepared) = prepared
        && matches!(identity.instance, RecordedIdentity::Absent { .. })
        && matches!(
            identity.containment,
            ContainmentFact::Contained {
                kind: se_store::ContainmentKind::Job,
                ..
            }
        )
    {
        // Unlike an uncontained tree, the original Windows job can
        // independently prove closure before any root was published.
        // Keep its protected bytes: normal startup still has to commit
        // retirement, revoke credentials and remove the exact files.
        se_proc::observe_prepared_scope_exit(prepared)
            .map_err(|error| unreadable(&format!("{error:?}")))?;
        return Ok(true);
    }
    Ok(false)
}
fn resolve_guard_record(
    checkpoint: &se_proc::Checkpoint,
    state: ProcessState,
) -> Result<(&ProcessRecord, bool)> {
    match checkpoint
        .owner_guard_record()
        .map_err(|error| unreadable(&error.to_string()))?
    {
        Some(record) => Ok((record, false)),
        None => match (&checkpoint.checkpoint, state) {
            // Native exit is committed before final capture/session cleanup.
            // Keep the original process in the ancestry inventory while that
            // debt is reconciled; do not turn a terminal marker into absence
            // or use its old witness as a fresh native observation.
            (CheckpointKind::Exit { source, .. }, ProcessState::Exited) => match source.as_ref() {
                CheckpointSource::Process(record) => Ok((record, true)),
                _ => Err(unreadable(
                    "terminal cleanup lacks an identified process source for owner ancestry",
                )),
            },
            _ => Err(unreadable(
                "terminal checkpoint contradicts an unresolved process index; reconcile the index before owner admission",
            )),
        },
    }
}
fn verify_recorded_root(
    record: &ProcessRecord,
    identity: &se_store::ProcessIdentityRecord,
) -> Result<()> {
    let RecordedIdentity::Present(instance) = &identity.instance else {
        return Err(unreadable(
            "published custody has no readable recorded root identity",
        ));
    };
    let fields = instance.fields();
    let started =
        crate::host_process::same_start(&record.root.start, &fields.started).unwrap_or(false);
    if record.root.machine != fields.machine
        || record.root.pid.0 != fields.pid.get()
        || !started
        || record.root.image != fields.executable.to_local()?
        || record.argv_sha256 != *fields.argv_sha256.as_bytes()
    {
        return Err(unreadable(
            "native checkpoint root machine/PID/birth/image/argv differs from its protected index",
        ));
    }
    Ok(())
}
fn state_matches(native: LifecycleState, stored: ProcessState) -> bool {
    // StopRequested is a FULL control-intent barrier before native effects;
    // StopUnproved can retain that same checkpoint after a failed observation.
    // Neither is a new native identity or an exit/release witness. The original
    // root and custody remain necessary for the independent ancestry check.
    if matches!(
        stored,
        ProcessState::StopRequested | ProcessState::StopUnproved
    ) && matches!(
        native,
        LifecycleState::Running
            | LifecycleState::LeaderExited
            | LifecycleState::StopRequested
            | LifecycleState::StopUnproved
    ) {
        return true;
    }
    matches!(
        (native, stored),
        (LifecycleState::Reserved, ProcessState::Reserved)
            | (LifecycleState::Starting, ProcessState::Starting)
            // The exact exec checkpoint precedes provider readiness and C3.
            | (LifecycleState::Running, ProcessState::Starting)
            | (LifecycleState::Running, ProcessState::Running)
            | (LifecycleState::LeaderExited, ProcessState::LeaderExited)
            | (LifecycleState::StopRequested, ProcessState::StopRequested)
            | (LifecycleState::StopUnproved, ProcessState::StopUnproved)
            | (LifecycleState::Lost, ProcessState::Lost)
    )
}
fn unreadable(reason: &str) -> se_types::SeError {
    se_core::scope::unreadable("protected native custody inventory", reason)
}
