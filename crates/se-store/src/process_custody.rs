//! The store's read of a host-owned custody checkpoint.
//!
//! The checkpoint is decoded through se-proc's own process codec, so a
//! receipt and an owner-guard recovery read exactly the bytes the native
//! codec validates. On top of that decode, the host binding must be complete:
//! the tagged host principal names this lifecycle's scope, the record serves
//! no single session, and the checkpoint's native owner and generation are
//! the recorded originating host epoch. A missing or inconsistent binding
//! refuses as unreadable custody, never as an unowned process.
use crate::{StoreError, StoreErrorCode, StoreResult, error::*};
use se_types::HostEpoch;

pub(crate) fn unreadable(why: &str) -> Box<StoreError> {
    fail(
        StoreErrorCode::Unreadable,
        format!("host-owned custody is unreadable: {why}"),
    )
}

/// The decoded checkpoint, verified as this lifecycle's host-owned custody.
pub(crate) fn decoded(
    custody: &crate::NativeCustody,
    lifecycle: &se_types::LifecycleId,
) -> StoreResult<se_proc::Checkpoint> {
    let checkpoint = se_proc::decode_checkpoint(custody.format_version, &custody.record)
        .map_err(|e| unreadable(&format!("process codec refused the custody: {e}")))?;
    if &checkpoint.lifecycle != lifecycle {
        return Err(unreadable(
            "custody is not this lifecycle's version-1 checkpoint",
        ));
    }
    if checkpoint.session.is_some() {
        return Err(unreadable("a host-owned process serves no single session"));
    }
    match &checkpoint.principal {
        se_proc::CheckpointPrincipal::Host { scope } if scope == lifecycle => Ok(checkpoint),
        _ => Err(unreadable(
            "custody does not carry the tagged host principal for this scope",
        )),
    }
}

/// The checkpoint's native owner/generation pair, whichever phase it records.
pub(crate) fn origin(
    checkpoint: &se_proc::Checkpoint,
) -> StoreResult<(se_proc::ProcessIdentity, se_proc::GenerationId)> {
    use se_proc::{CheckpointKind as Kind, CheckpointSource as Source};
    let (owner, generation) = match &checkpoint.checkpoint {
        Kind::Reservation(v) => (v.owner.clone(), v.generation),
        Kind::Scope(v) => (v.reservation.owner.clone(), v.reservation.generation),
        Kind::Root(v) => (
            v.scope.reservation.owner.clone(),
            v.scope.reservation.generation,
        ),
        Kind::Process(v) => (v.owner.clone(), v.generation),
        Kind::Exit { source, .. } | Kind::Released { source, .. } => match source.as_ref() {
            Source::Reservation(v) => (v.owner.clone(), v.generation),
            Source::Scope(v) => (v.reservation.owner.clone(), v.reservation.generation),
            Source::Root(v) => (
                v.scope.reservation.owner.clone(),
                v.scope.reservation.generation,
            ),
            Source::Process(v) => (v.owner.clone(), v.generation),
        },
        Kind::FailedReservation { reservation, .. } => {
            (reservation.owner.clone(), reservation.generation)
        }
        Kind::Historical(_) => {
            return Err(unreadable(
                "historical custody carries no live native owner",
            ));
        }
    };
    Ok((owner, generation))
}

/// Whether the checkpoint's native owner/generation is exactly this epoch's
/// host instance. The epoch's boot string is the platform's boot-environment
/// identity while the checkpoint carries the process clock's own boot fact,
/// so the instance comparison is machine, PID and native birth; the epoch's
/// generation pins the host run.
pub(crate) fn same_epoch(
    owner: &se_proc::ProcessIdentity,
    generation: se_proc::GenerationId,
    epoch: &HostEpoch,
) -> bool {
    let fields = epoch.owner.fields();
    let start_matches = match (&owner.start, &fields.started) {
        (
            se_proc::StartIdentity::Linux { start_ticks },
            se_types::StartIdentity::Linux {
                start_ticks: expected,
            },
        ) => start_ticks == expected,
        (
            se_proc::StartIdentity::Windows { creation_filetime },
            se_types::StartIdentity::Windows {
                creation_filetime: expected,
            },
        ) => *creation_filetime == expected.get(),
        (
            se_proc::StartIdentity::MacOs {
                seconds,
                microseconds,
            },
            se_types::StartIdentity::Macos {
                start_seconds,
                start_micros,
            },
        ) => seconds == start_seconds && microseconds == start_micros,
        _ => false,
    };
    owner.machine == fields.machine
        && owner.pid.0 == fields.pid.get()
        && start_matches
        && generation.get() == epoch.generation.get()
}
