//! Join the one native checkpoint codec to protected store indices. This adapter
//! neither deserializes a second format nor reconstructs native handles.
use se_proc::{CheckpointPrincipal, LifecycleState, ProcessRecord, RootPublication};
use se_store::{Actor, OwnerGuardInventory, ProcessState, RecordedIdentity, RootIdentityState};
use se_types::{Result, StartIdentity};

pub fn decode_owner_inventory(inventory: &OwnerGuardInventory) -> Result<Vec<ProcessRecord>> {
    let mut records = Vec::with_capacity(inventory.processes.len());
    for entry in &inventory.processes {
        let identity = &entry.identity;
        let checkpoint =
            se_proc::decode_checkpoint(identity.custody.format_version, &identity.custody.record)
                .map_err(|error| unreadable(&error.to_string()))?;
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
        let record = checkpoint.owner_guard_record()
            .map_err(|error| unreadable(&error.to_string()))?
            .ok_or_else(|| unreadable("terminal checkpoint contradicts an unresolved process index; reconcile the index before owner admission"))?;
        if !state_matches(record.state, entry.state) || record.ownership_release.is_some() {
            return Err(unreadable(
                "checkpoint state/release differs from the protected unresolved process index",
            ));
        }
        let RecordedIdentity::Present(instance) = &identity.instance else {
            return Err(unreadable(
                "published custody has no readable recorded root identity",
            ));
        };
        let fields = instance.fields();
        let started = match (&record.root.start, &fields.started) {
            (
                se_proc::StartIdentity::Linux { start_ticks: a },
                StartIdentity::Linux { start_ticks: b },
            ) => a == b,
            (
                se_proc::StartIdentity::Windows {
                    creation_filetime: a,
                },
                StartIdentity::Windows {
                    creation_filetime: b,
                },
            ) => *a == b.get(),
            (
                se_proc::StartIdentity::MacOs {
                    seconds: a,
                    microseconds: b,
                },
                StartIdentity::Macos {
                    start_seconds: c,
                    start_micros: d,
                },
            ) => a == c && b == d,
            _ => false,
        };
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
        // BootId is an opaque display/transport label, with no native encoding
        // contract. The decoded native boot/start pair is validated by the codec
        // and checked against the kernel by observe_owner; it is never replaced
        // by that label or by PID-only discovery here.
        records.push(record.clone());
    }
    Ok(records)
}
fn state_matches(native: LifecycleState, stored: ProcessState) -> bool {
    matches!(
        (native, stored),
        (LifecycleState::Reserved, ProcessState::Reserved)
            | (LifecycleState::Starting, ProcessState::Starting)
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
