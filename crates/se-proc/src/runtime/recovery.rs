use super::SlotEntry;
#[cfg(target_os = "linux")]
use super::{Slot, notify::Hub};
use crate::support::*;
use crate::*;
#[cfg(target_os = "linux")]
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

pub(super) fn plan(
    _runtime: &NativeProcessRuntime,
    source: RecoverySource,
) -> ProcResult<RecoveryPlan> {
    crate::checkpoint::validate_recovery(&source)
        .map_err(|e| input("recovery source", &e.to_string()))?;
    let disposition = match &source {
        RecoverySource::Record(record) => {
            if record.format_version != 1 {
                return Err(input("process record", "unsupported version"));
            }
            if record.state == LifecycleState::Historical {
                RecoveryDisposition::Historical
            } else if let Some(release) = &record.ownership_release {
                if release.lifecycle != record.lifecycle
                    || release.generation != record.generation
                    || release.scope != record.scope
                    || !matches!(
                        record.scope,
                        ScopeIdentity::LinuxTracked { .. } | ScopeIdentity::MacOsTracked { .. }
                    )
                    || record.state != LifecycleState::StopUnproved
                {
                    return Err(input(
                        "ownership release",
                        "marker does not match its StopUnproved tracked record",
                    ));
                }
                RecoveryDisposition::ReleaseUncontainedOwnership
            } else if record.state == LifecycleState::Exited {
                RecoveryDisposition::ReleaseExitedScope
            } else if matches!(record.scope, ScopeIdentity::WindowsJob { .. }) {
                RecoveryDisposition::VerifyExitedThenResume
            } else {
                RecoveryDisposition::ReattachLinuxScope
            }
        }
        _ => RecoveryDisposition::ReconcileReservation,
    };
    Ok(RecoveryPlan {
        source,
        disposition,
    })
}
#[cfg(target_os = "linux")]
struct Silent;
#[cfg(target_os = "linux")]
impl ExitSink for Silent {
    fn notify(&self, _notice: ExitNotice) {}
}
pub(super) fn recover(
    runtime: &NativeProcessRuntime,
    supplied: RecoveryPlan,
    generation: GenerationId,
) -> ProcResult<RecoveryOutcome> {
    let checked = plan(runtime, supplied.source.clone())?;
    if supplied.disposition != checked.disposition {
        return Err(input(
            "recovery plan",
            "disposition differs from protected source",
        ));
    }
    if checked.disposition == RecoveryDisposition::Historical {
        return Ok(unproved(
            checked.source,
            "historical records never grant live custody",
        ));
    }
    if let RecoverySource::Record(record) = &checked.source
        && let Some(release) = &record.ownership_release
    {
        // A committed release never creates a native owner, even if a
        // process with those same bytes is still running.
        return Ok(RecoveryOutcome::ReleasedOwnership(Box::new(
            ReleasedOwnership {
                release: release.clone(),
            },
        )));
    }
    let reservation = match &checked.source {
        RecoverySource::Reservation(r) => (**r).clone(),
        RecoverySource::Prepared(c) => c.reservation.clone(),
        RecoverySource::RootPrepared(c) => c.scope.reservation.clone(),
        RecoverySource::Record(record) => LaunchReservation {
            format_version: 1,
            lifecycle: record.lifecycle.clone(),
            host: record.host,
            owner: record.owner.clone(),
            generation: record.generation,
            scope_nonce: [0; 16],
            parent: match &record.scope {
                ScopeIdentity::WindowsJob { .. } => ReservationParent::Windows,
                ScopeIdentity::LinuxTracked { .. } => ReservationParent::LinuxTracked,
                _ => {
                    return Ok(unproved(
                        checked.source,
                        "scope is outside the implemented wave-1 recovery path",
                    ));
                }
            },
            created_at_unix_ns: record.observed_at_unix_ns,
        },
    };
    if reservation.owner.machine != runtime.inner.config.machine {
        return Err(input("recovery", "record belongs to another machine"));
    }
    let existing = {
        let mut slots = runtime
            .inner
            .slots
            .lock()
            .map_err(|_| input("recovery", "arena map poisoned"))?;
        if let Some(slot) = slots.get(&reservation.lifecycle).and_then(SlotEntry::owned) {
            Some(slot)
        } else if let RecoverySource::Reservation(reserved) = &checked.source
            && reserved.host == runtime.inner.config.instance
            && reserved.owner == runtime.inner.owner
            && reserved.generation == generation
        {
            if let Some(SlotEntry::Retired(previous)) = slots.get(&reservation.lifecycle)
                && previous != reserved
            {
                return Err(input(
                    "reservation retirement",
                    "retained reservation differs",
                ));
            }
            if !slots.contains_key(&reservation.lifecycle)
                && slots.len() >= runtime.inner.config.limits.max_lifecycles as usize
            {
                return Err(capacity(
                    "native lifecycle entries",
                    runtime.inner.config.limits.max_lifecycles as u64,
                ));
            }
            // The same lock arbitrates prepare_launch. Retain the exact C1
            // reservation so a late prepare cannot follow this empty witness.
            let outcome = uncreated(reserved)?;
            slots.insert(
                reservation.lifecycle.clone(),
                SlotEntry::Retired(reserved.clone()),
            );
            runtime.inner.bump();
            return Ok(outcome);
        } else if slots.contains_key(&reservation.lifecycle) {
            return Err(input(
                "reservation retirement",
                "this lifecycle is already retired",
            ));
        } else {
            None
        }
    };
    if let Some(slot) = existing {
        let from = slot
            .lock()
            .map_err(|_| input("recovery", "slot requires quarantine cleanup"))?
            .generation;
        let key = runtime
            .inner
            .reference(&slot, reservation.lifecycle.clone(), from);
        return runtime.inner.apply(&key, true, |s| {
            if s.reservation.lifecycle != reservation.lifecycle
                || s.reservation.host != reservation.host
                || s.reservation.owner != reservation.owner
            {
                return Err(input(
                    "recovery",
                    "source differs from retained native owner",
                ));
            }
            if generation != from
                && generation.get()
                    != from
                        .get()
                        .checked_add(1)
                        .ok_or_else(|| input("generation", "exhausted"))?
            {
                return Err(input(
                    "recovery generation",
                    "same or immediate successor required",
                ));
            }
            if let (Some(record), RecoverySource::Record(expected)) = (&s.record, &checked.source)
                && (record.root != expected.root || record.scope != expected.scope)
            {
                return Err(changed(&record.root, Some(&expected.root)));
            }
            s.generation = generation;
            s.hub.generation(generation);
            if let Some(record) = &mut s.record {
                record.generation = generation;
                return Ok(RecoveryOutcome::Recovered {
                    process: OwnedProcess {
                        key: runtime.inner.reference(
                            &slot,
                            reservation.lifecycle.clone(),
                            generation,
                        ),
                    },
                    record: Box::new(record.clone()),
                });
            }
            if let Some(checkpoint) = &s.checkpoint {
                return Ok(RecoveryOutcome::PendingScope {
                    process: OwnedProcess {
                        key: runtime.inner.reference(
                            &slot,
                            reservation.lifecycle.clone(),
                            generation,
                        ),
                    },
                    checkpoint: Box::new(checkpoint.clone()),
                });
            }
            if !s.launched && s.native.is_none() {
                let (empty, guarantee) = crate::platform::uncreated_scope(&s.reservation)?;
                return Ok(RecoveryOutcome::PendingScope {
                    process: OwnedProcess {
                        key: runtime.inner.reference(
                            &slot,
                            reservation.lifecycle.clone(),
                            generation,
                        ),
                    },
                    checkpoint: Box::new(ScopeCheckpoint {
                        reservation: s.reservation.clone(),
                        parent: match empty.scope {
                            ScopeIdentity::LinuxPrepared { .. } => ReservationParent::LinuxTracked,
                            ScopeIdentity::WindowsJob { .. } => ReservationParent::Windows,
                            _ => {
                                return Err(input(
                                    "failed preparation",
                                    "unrecognized vendor-free scope",
                                ));
                            }
                        },
                        scope: empty.scope,
                        guarantee,
                    }),
                });
            }
            Ok(unproved(
                checked.source.clone(),
                "reservation retained without a reconciled native scope",
            ))
        });
    }
    #[cfg(windows)]
    {
        match runtime.inner.driver.reconcile(&checked.source) {
            Ok(witness) => Ok(RecoveryOutcome::Exited(Box::new(witness))),
            Err(error) => Ok(RecoveryOutcome::Unproved {
                source: Box::new(checked.source),
                error,
            }),
        }
    }
    #[cfg(target_os = "linux")]
    cold_linux(runtime, checked, reservation, generation)
}
#[cfg(target_os = "linux")]
fn cold_linux(
    runtime: &NativeProcessRuntime,
    checked: RecoveryPlan,
    reservation: LaunchReservation,
    generation: GenerationId,
) -> ProcResult<RecoveryOutcome> {
    if let RecoverySource::Reservation(reserved) = &checked.source {
        let owner = super::read_process(reserved.owner.machine.clone(), reserved.owner.pid)?;
        let gone = match owner {
            ProcessRead::Absent { .. } => true,
            ProcessRead::ExitedRecord { boot, start, .. } => {
                boot == reserved.owner.boot && start == reserved.owner.start
            }
            ProcessRead::Present(live) => {
                live.identity.boot != reserved.owner.boot
                    || live.identity.start != reserved.owner.start
            }
        };
        if gone {
            return uncreated(reserved);
        }
        return Ok(unproved(
            checked.source,
            "original owner still live; reservation cannot be retired by another arena",
        ));
    }
    let RecoverySource::Record(record) = &checked.source else {
        return Ok(unproved(
            checked.source,
            "cold prepared/root custody remains unproved; no recovery child was created and no numeric group was signalled",
        ));
    };
    match runtime
        .inner
        .driver
        .reconcile(record, runtime.inner.config.limits)
    {
        Ok(Some(witness)) => return Ok(RecoveryOutcome::Exited(Box::new(witness))),
        Ok(None) => (),
        Err(error) => {
            return Ok(RecoveryOutcome::Unproved {
                source: Box::new(checked.source),
                error,
            });
        }
    }
    let hub = Arc::new(Hub::new(
        record.lifecycle.clone(),
        generation,
        Arc::new(Silent),
    ));
    // Reserve capacity before native recovery obtains any new descriptor.
    let slot = Arc::new(Mutex::new(Slot {
        reservation: reservation.clone(),
        checkpoint: None,
        root_checkpoint: None,
        record: None,
        native: None,
        spec: None,
        stdio_bound: true,
        #[cfg(windows)]
        stdio: None,
        deadline: Instant::now(),
        argv_sha256: record.argv_sha256,
        hub: hub.clone(),
        generation,
        phase: LifecycleState::Lost,
        launched: true,
        released: false,
        poisoned: false,
        failure: None,
        stop_prepared: 0,
        stop_consumed: 0,
        stop_attempt: 0,
    }));
    {
        let mut slots = runtime
            .inner
            .slots
            .lock()
            .map_err(|_| input("recovery", "arena map poisoned"))?;
        if slots.contains_key(&record.lifecycle) {
            return Err(input(
                "recovery",
                "concurrent recovery won; reread the arena",
            ));
        }
        if slots.len() >= runtime.inner.config.limits.max_lifecycles as usize {
            return Err(capacity(
                "native lifecycle entries",
                runtime.inner.config.limits.max_lifecycles as u64,
            ));
        }
        slots.insert(record.lifecycle.clone(), SlotEntry::Owned(slot.clone()));
        runtime.inner.bump();
    }
    let key = runtime
        .inner
        .reference(&slot, record.lifecycle.clone(), generation);
    let result = runtime.inner.apply(&key, false, |s| {
        let native = runtime
            .inner
            .driver
            .recover(record, runtime.inner.config.limits, &hub)?;
        s.native = Some(native);
        let mut current = (**record).clone();
        current.host = runtime.inner.config.instance;
        current.owner = runtime.inner.owner.clone();
        current.generation = generation;
        s.phase = current.state;
        s.record = Some(current.clone());
        Ok(current)
    });
    match result {
        Ok(record) => Ok(RecoveryOutcome::Recovered {
            process: OwnedProcess { key },
            record: Box::new(record),
        }),
        Err(error) => {
            runtime.inner.remove(&key)?;
            Ok(RecoveryOutcome::Unproved {
                source: Box::new(checked.source),
                error,
            })
        }
    }
}
fn unproved(source: RecoverySource, reason: &str) -> RecoveryOutcome {
    RecoveryOutcome::Unproved {
        source: Box::new(source),
        error: error(
            ProcErrorCode::RecoveryUnproved,
            ProcErrorDetail::Input {
                field: "recovery".into(),
                reason: reason.into(),
            },
        ),
    }
}

fn uncreated(reservation: &LaunchReservation) -> ProcResult<RecoveryOutcome> {
    let (scope_exit, guarantee) = crate::platform::uncreated_scope(reservation)?;
    Ok(RecoveryOutcome::Exited(Box::new(StopWitness {
        lifecycle: reservation.lifecycle.clone(),
        root: RootWitness::NoChildCreated,
        scope: scope_exit.scope.clone(),
        scope_exit,
        guarantee,
        observed_at_unix_ns: now()?,
    })))
}
