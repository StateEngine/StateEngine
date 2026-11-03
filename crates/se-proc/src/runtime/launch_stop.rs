//! ProcessRuntime adapter, arena observation and same-host adoption.
mod launch;
mod stop;
use super::{Arena, Slot, SlotEntry, notify::Hub, validate};
use crate::platform::Progress;
use crate::support::*;
use crate::*;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

impl ProcessRuntime for NativeProcessRuntime {
    fn open(config: HostConfig) -> ProcResult<Self> {
        if config.limits.max_lifecycles == 0
            || config.limits.max_diagnostic_members == 0
            || config.limits.max_observation_bytes < 4096
        {
            return Err(input(
                "resource limits",
                "positive lifecycle/member limits and at least 4096 observation bytes required",
            ));
        }
        let ProcessRead::Present(owner) =
            super::read_process(config.machine.clone(), ProcessId(std::process::id()))?
        else {
            return Err(input("runtime owner", "current native instance unreadable"));
        };
        let driver = crate::platform::Driver::new(&config)?;
        Ok(Self {
            inner: Arc::new(Arena {
                config,
                owner: owner.identity,
                driver,
                slots: Mutex::new(HashMap::new()),
                revision: AtomicU64::new(0),
            }),
        })
    }
    fn capabilities(&self) -> ProcResult<PlatformCapabilities> {
        Ok(self.inner.driver.capabilities())
    }
    fn arena_snapshot(&self) -> ProcResult<ArenaSnapshot> {
        for _ in 0..3 {
            let before = self.inner.revision.load(Ordering::Acquire);
            let slots = self
                .inner
                .slots
                .lock()
                .map_err(|_| {
                    error(
                        ProcErrorCode::LockPoisoned,
                        ProcErrorDetail::Internal {
                            location: "arena snapshot".into(),
                            report_id: [0; 16],
                        },
                    )
                })?
                .values()
                .filter_map(SlotEntry::owned)
                .collect::<Vec<_>>();
            let mut entries = Vec::with_capacity(slots.len());
            for slot in slots {
                let slot = match slot.lock() {
                    Ok(s) => s,
                    Err(e) => {
                        let mut s = e.into_inner();
                        s.poisoned = true;
                        s
                    }
                };
                if !slot.released {
                    entries.push(slot.snapshot());
                }
            }
            if before == self.inner.revision.load(Ordering::Acquire) {
                // A bounded complete view, never a silently clipped census.
                return Ok(ArenaSnapshot {
                    entries,
                    complete: true,
                    revision: before,
                });
            }
        }
        Err(input(
            "arena snapshot",
            "concurrent native changes prevented a coherent snapshot; retry",
        ))
    }
    fn prepare_launch(
        &self,
        reservation: LaunchReservation,
        spec: LaunchSpec,
    ) -> ProcResult<PreparedScope> {
        self.native_prepare_launch(reservation, spec)
    }
    fn bind_stdio(&self, prepared: &PreparedLaunch, child: StandardIo) -> ProcResult<()> {
        self.native_bind_stdio(prepared, child)
    }
    fn begin_launch(&self, prepared: PreparedLaunch) -> LaunchStart {
        self.native_begin_launch(prepared)
    }
    fn poll_launch(&self, ticket: &LaunchTicket) -> ProcResult<LaunchProgress> {
        self.native_poll_launch(ticket)
    }
    fn authorize_exec(&self, ticket: &LaunchTicket) -> ProcResult<()> {
        self.native_authorize_exec(ticket)
    }
    fn cancel_launch(
        &self,
        ticket: LaunchTicket,
        prepared: PreparedStop,
    ) -> ProcResult<StopAttempt> {
        self.native_cancel_launch(ticket, prepared)
    }
    fn describe(&self, process: &OwnedProcess) -> ProcResult<ProcessRecord> {
        self.inner.apply(&process.key, true, |s| s.record())
    }
    fn observe(&self, process: &OwnedProcess) -> ProcResult<OwnedObservation> {
        self.inner.apply(&process.key, true, |s| {
            let root = s
                .native()?
                .root()?
                .ok_or_else(|| input("observe", "no root record; use arena_snapshot"))?;
            let scope = s.native()?.observe()?;
            if matches!(root, ProcessObservation::Exited { .. }) {
                let complete = scope.remaining.population == Population::Empty
                    && scope.exit_basis.is_some()
                    && matches!(scope.remaining.extent, EnumerationExtent::Complete);
                s.set_phase(if complete {
                    LifecycleState::Exited
                } else if scope.remaining.population == Population::Empty {
                    LifecycleState::StopUnproved
                } else {
                    LifecycleState::LeaderExited
                })?;
            }
            if let ProcessObservation::Exited { status, .. } = &root
                && let Some(record) = &mut s.record
            {
                record.exit_status = Some(status.clone());
            }
            Ok(OwnedObservation {
                record: s.record()?,
                root,
                scope,
            })
        })
    }
    fn watch_exit(&self, process: &OwnedProcess, sink: Arc<dyn ExitSink>) -> ProcResult<ExitWatch> {
        let hub = self
            .inner
            .apply(&process.key, true, |s| Ok(s.hub.clone()))?;
        Ok(ExitWatch {
            _watch: hub.watch(sink)?,
        })
    }
    fn re_adopt(
        &self,
        record: &ProcessRecord,
        from: GenerationId,
        to: GenerationId,
    ) -> ProcResult<OwnedProcess> {
        let slot = self
            .inner
            .slots
            .lock()
            .map_err(|_| input("arena", "map poisoned"))?
            .get(&record.lifecycle)
            .and_then(SlotEntry::owned)
            .ok_or_else(|| input("re_adopt", "not in this arena; use cold recovery"))?;
        let key = self.inner.reference(&slot, record.lifecycle.clone(), from);
        self.inner.apply(&key, false, |s| {
            let actual = s.record()?;
            if actual.root != record.root
                || actual.scope != record.scope
                || actual.host != record.host
                || actual.ownership_release.is_some()
                || record.ownership_release.is_some()
            {
                return Err(changed(&actual.root, Some(&record.root)));
            }
            if to != from
                && to.get()
                    != from
                        .get()
                        .checked_add(1)
                        .ok_or_else(|| input("generation", "exhausted"))?
            {
                return Err(input("generation", "same or next generation required"));
            }
            #[cfg(windows)]
            if to != from
                && let Some(stdio) = &s.stdio
            {
                stdio.fence(to)?;
            }
            s.generation = to;
            if let Some(record) = &mut s.record {
                record.generation = to;
            }
            s.hub.generation(to);
            Ok(())
        })?;
        Ok(OwnedProcess {
            key: self.inner.reference(&slot, record.lifecycle.clone(), to),
        })
    }
    fn prepare_stop(
        &self,
        process: &OwnedProcess,
        generation: GenerationId,
        deadline: Instant,
    ) -> ProcResult<PreparedStop> {
        self.native_prepare_stop(process, generation, deadline)
    }
    fn request_stop(&self, prepared: PreparedStop) -> ProcResult<StopAttempt> {
        self.native_request_stop(prepared)
    }
    fn witness_stop(&self, ticket: &StopTicket) -> ProcResult<StopObservation> {
        self.native_witness_stop(ticket)
    }
    fn witness_exit(&self, process: &OwnedProcess) -> ProcResult<StopObservation> {
        self.native_witness_exit(process)
    }
    fn release(&self, process: &OwnedProcess, supplied: &StopWitness) -> ProcResult<()> {
        self.native_release(process, supplied)
    }
    fn release_uncontained(
        &self,
        process: &OwnedProcess,
        release: &UnwitnessedRelease,
    ) -> ProcResult<ReleasedOwnership> {
        self.native_release_uncontained(process, release)
    }
    fn plan_recovery(&self, source: RecoverySource) -> ProcResult<RecoveryPlan> {
        super::recovery::plan(self, source)
    }
    fn recover(&self, plan: RecoveryPlan, generation: GenerationId) -> ProcResult<RecoveryOutcome> {
        super::recovery::recover(self, plan, generation)
    }
}
