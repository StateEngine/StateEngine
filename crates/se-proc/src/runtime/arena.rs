use super::notify::Hub;
use crate::support::*;
use crate::*;
use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

pub(crate) struct Arena {
    pub config: HostConfig,
    pub owner: ProcessIdentity,
    pub driver: crate::platform::Driver,
    pub slots: Mutex<HashMap<LifecycleId, Arc<Mutex<Slot>>>>,
    pub revision: AtomicU64,
}
#[derive(Clone)]
pub(crate) struct Reference {
    pub arena: Weak<Arena>,
    pub slot: Weak<Mutex<Slot>>,
    pub lifecycle: LifecycleId,
    pub generation: GenerationId,
}
pub(crate) struct Slot {
    pub reservation: LaunchReservation,
    pub checkpoint: Option<ScopeCheckpoint>,
    pub root_checkpoint: Option<RootCheckpoint>,
    pub record: Option<ProcessRecord>,
    pub native: Option<crate::platform::Scope>,
    pub spec: Option<LaunchSpec>,
    pub stdio_bound: bool,
    #[cfg(windows)]
    pub stdio: Option<Arc<crate::platform::NativeStdio>>,
    pub deadline: std::time::Instant,
    pub argv_sha256: [u8; 32],
    pub hub: Arc<Hub>,
    pub generation: GenerationId,
    pub phase: LifecycleState,
    pub launched: bool,
    pub released: bool,
    pub poisoned: bool,
    pub failure: Option<ProcError>,
    pub stop_prepared: u64,
    pub stop_consumed: u64,
    pub stop_attempt: u64,
}
impl Arena {
    pub fn bump(&self) {
        self.revision.fetch_add(1, Ordering::AcqRel);
    }
    pub fn reference(
        self: &Arc<Self>,
        slot: &Arc<Mutex<Slot>>,
        lifecycle: LifecycleId,
        generation: GenerationId,
    ) -> Reference {
        Reference {
            arena: Arc::downgrade(self),
            slot: Arc::downgrade(slot),
            lifecycle,
            generation,
        }
    }
    pub fn apply<T>(
        &self,
        key: &Reference,
        cleanup: bool,
        operation: impl FnOnce(&mut Slot) -> ProcResult<T>,
    ) -> ProcResult<T> {
        let arena = key
            .arena
            .upgrade()
            .ok_or_else(|| input("custody reference", "runtime has closed"))?;
        if !std::ptr::eq(self, Arc::as_ptr(&arena)) {
            return Err(error(
                ProcErrorCode::HostChanged,
                ProcErrorDetail::Host {
                    expected: arena.config.instance,
                    current: self.config.instance,
                },
            ));
        }
        let slot = key
            .slot
            .upgrade()
            .ok_or_else(|| input("custody reference", "lifecycle has been released"))?;
        let mut slot = match slot.lock() {
            Ok(s) => s,
            Err(e) => {
                let mut s = e.into_inner();
                s.poisoned = true;
                if !cleanup {
                    return Err(error(
                        ProcErrorCode::LockPoisoned,
                        ProcErrorDetail::Internal {
                            location: "native slot".into(),
                            report_id: [0; 16],
                        },
                    ));
                }
                s
            }
        };
        if slot.released {
            return Err(state(&key.lifecycle, slot.phase, "use released custody"));
        }
        if slot.generation != key.generation {
            return Err(error(
                ProcErrorCode::GenerationChanged,
                ProcErrorDetail::Generation {
                    expected: key.generation,
                    current: slot.generation,
                },
            ));
        }
        if slot.hub.failed.load(Ordering::Acquire) {
            slot.poisoned = true;
            slot.failure = Some(error(
                ProcErrorCode::CallbackPanicked,
                ProcErrorDetail::Internal {
                    location: "exit callback".into(),
                    report_id: [0; 16],
                },
            ));
        }
        if slot.poisoned && !cleanup {
            return Err(slot.failure.clone().unwrap_or_else(|| {
                error(
                    ProcErrorCode::LockPoisoned,
                    ProcErrorDetail::Internal {
                        location: "quarantined native slot".into(),
                        report_id: [0; 16],
                    },
                )
            }));
        }
        let result = catch_unwind(AssertUnwindSafe(|| operation(&mut slot)));
        self.bump();
        match result {
            Ok(value) => value,
            Err(_) => {
                slot.poisoned = true;
                let failure = error(
                    ProcErrorCode::OperationPanicked,
                    ProcErrorDetail::Internal {
                        location: "native operation".into(),
                        report_id: [0; 16],
                    },
                );
                slot.failure = Some(failure.clone());
                Err(failure)
            }
        }
    }
    pub fn remove(&self, key: &Reference) -> ProcResult<()> {
        let mut map = self.slots.lock().map_err(|_| {
            error(
                ProcErrorCode::LockPoisoned,
                ProcErrorDetail::Internal {
                    location: "arena map".into(),
                    report_id: [0; 16],
                },
            )
        })?;
        if map
            .get(&key.lifecycle)
            .is_some_and(|slot| Weak::ptr_eq(&Arc::downgrade(slot), &key.slot))
        {
            map.remove(&key.lifecycle);
            self.bump();
        }
        Ok(())
    }
}
impl Slot {
    pub fn native(&mut self) -> ProcResult<&mut crate::platform::Scope> {
        self.native.as_mut().ok_or_else(|| {
            input(
                "native scope",
                "scope preparation has not completed; inspect the reservation",
            )
        })
    }
    pub fn record(&self) -> ProcResult<ProcessRecord> {
        self.record.clone().ok_or_else(|| {
            state(
                &self.reservation.lifecycle,
                self.phase,
                "read a root record before exec; use arena_snapshot",
            )
        })
    }
    pub fn set_phase(&mut self, phase: LifecycleState) -> ProcResult<()> {
        let observed = now()?;
        self.phase = phase;
        if let Some(record) = &mut self.record {
            record.state = phase;
            record.observed_at_unix_ns = observed;
        }
        Ok(())
    }
    pub fn snapshot(&self) -> ArenaEntry {
        ArenaEntry {
            reservation: self.reservation.clone(),
            record: self.record.clone(),
            checkpoint: self.checkpoint.clone(),
            root_checkpoint: self.root_checkpoint.clone(),
            phase: self.phase,
            poisoned: self.poisoned,
        }
    }
}
