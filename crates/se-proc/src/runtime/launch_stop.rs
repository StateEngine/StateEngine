use super::{Arena, Slot, notify::Hub, validate};
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
                .cloned()
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
        let digest = validate::spec(&reservation, &spec, &self.inner.config, &self.inner.owner)?;
        let lifecycle = reservation.lifecycle.clone();
        let generation = reservation.generation;
        let hub = Arc::new(Hub::new(
            lifecycle.clone(),
            generation,
            spec.notifications.clone(),
        ));
        let deadline = spec.deadline;
        let slot = Arc::new(Mutex::new(Slot {
            reservation: reservation.clone(),
            checkpoint: None,
            root_checkpoint: None,
            record: None,
            native: None,
            spec: Some(spec),
            deadline,
            argv_sha256: digest,
            hub: hub.clone(),
            generation,
            phase: LifecycleState::Reserved,
            launched: false,
            released: false,
            poisoned: false,
            failure: None,
            stop_prepared: 0,
            stop_consumed: 0,
            stop_attempt: 0,
        }));
        {
            let mut slots = self.inner.slots.lock().map_err(|_| {
                error(
                    ProcErrorCode::LockPoisoned,
                    ProcErrorDetail::Internal {
                        location: "reserve native slot".into(),
                        report_id: [0; 16],
                    },
                )
            })?;
            if slots.contains_key(&lifecycle) {
                return Err(error(
                    ProcErrorCode::DuplicateLifecycle,
                    ProcErrorDetail::State {
                        lifecycle,
                        from: LifecycleState::Reserved,
                        operation: "reserve duplicate lifecycle".into(),
                    },
                ));
            }
            if slots.len() >= self.inner.config.limits.max_lifecycles as usize {
                return Err(capacity(
                    "active native lifecycles",
                    self.inner.config.limits.max_lifecycles as u64,
                ));
            }
            slots.insert(lifecycle.clone(), slot.clone());
            self.inner.bump();
        }
        let key = self.inner.reference(&slot, lifecycle.clone(), generation);
        let result = self.inner.apply(&key, false, |s| {
            let spec = s
                .spec
                .as_ref()
                .ok_or_else(|| input("launch", "missing prepared spec"))?;
            let native = self.inner.driver.prepare(
                &s.reservation,
                spec,
                self.inner.config.limits,
                &s.hub,
            )?;
            s.native = Some(native);
            let native = s.native()?;
            let checkpoint = ScopeCheckpoint {
                reservation: reservation.clone(),
                parent: native.parent(),
                scope: native.scope.clone(),
                guarantee: native.guarantee,
            };
            s.checkpoint = Some(checkpoint.clone());
            s.set_phase(LifecycleState::Starting)?;
            Ok(checkpoint)
        });
        match result {
            Ok(checkpoint) => Ok(PreparedScope {
                prepared: PreparedLaunch { key: key.clone() },
                process: OwnedProcess { key },
                checkpoint,
            }),
            Err(e) => {
                // Preparation creates no vendor child. A successfully allocated
                // scope remains discoverable through the reservation snapshot.
                let _ = self.inner.apply(&key, true, |s| {
                    s.failure = Some(e.clone());
                    Ok(())
                });
                Err(e)
            }
        }
    }
    fn begin_launch(&self, prepared: PreparedLaunch) -> LaunchStart {
        let key = prepared.key;
        let result = self.inner.apply(&key, false, |s| {
            if s.launched || s.phase != LifecycleState::Starting {
                return Err(state(&key.lifecycle, s.phase, "begin_launch"));
            }
            if Instant::now() >= s.deadline {
                return Err(error(
                    ProcErrorCode::LaunchTimedOut,
                    ProcErrorDetail::Input {
                        field: "deadline".into(),
                        reason: "launch deadline elapsed before child creation".into(),
                    },
                ));
            }
            s.launched = true;
            let spec = s
                .spec
                .take()
                .ok_or_else(|| input("launch spec", "already consumed"))?;
            let hub = s.hub.clone();
            self.inner.driver.begin(s.native()?, spec, &hub)
        });
        match result {
            Ok(()) => LaunchStart::Pending {
                ticket: LaunchTicket { key: key.clone() },
                process: OwnedProcess { key },
            },
            Err(e) => {
                let _ = self.inner.apply(&key, true, |s| {
                    s.failure = Some(e.clone());
                    Ok(())
                });
                LaunchStart::Failed(Box::new(LaunchFailure {
                    error: e,
                    remaining: Some(OwnedProcess { key }),
                    rollback: None,
                }))
            }
        }
    }
    fn poll_launch(&self, ticket: &LaunchTicket) -> ProcResult<LaunchProgress> {
        let result = self.inner.apply(&ticket.key, false, |s| {
            if let Some(error) = &s.failure {
                return Ok(LaunchProgress::Failed(Box::new(LaunchFailure {
                    error: error.clone(),
                    remaining: Some(OwnedProcess {
                        key: ticket.key.clone(),
                    }),
                    rollback: None,
                })));
            }
            if let Some(record) = &s.record {
                let record = record.clone();
                let root = s
                    .native()?
                    .root()?
                    .ok_or_else(|| input("root", "published root missing"))?;
                return Ok(LaunchProgress::Started(Box::new(LaunchSuccess {
                    process: OwnedProcess {
                        key: ticket.key.clone(),
                    },
                    record,
                    exec_observed: root,
                })));
            }
            if Instant::now() >= s.deadline {
                return Err(error(
                    ProcErrorCode::LaunchTimedOut,
                    ProcErrorDetail::Input {
                        field: "deadline".into(),
                        reason: "native launch did not finish by its original deadline".into(),
                    },
                ));
            }
            match s.native()?.poll(&self.inner.config.machine)? {
                #[cfg(target_os = "linux")]
                Progress::Pending => Ok(LaunchProgress::Pending),
                #[cfg(target_os = "linux")]
                Progress::Root(pre_exec) => {
                    let checkpoint = ScopeCheckpoint {
                        reservation: s.reservation.clone(),
                        parent: s.native()?.parent(),
                        scope: s.native()?.scope.clone(),
                        guarantee: s.native()?.guarantee,
                    };
                    let intended_executable = s.native()?.intended_executable();
                    let root = RootCheckpoint {
                        scope: checkpoint,
                        pre_exec,
                        intended_executable,
                    };
                    s.root_checkpoint = Some(root.clone());
                    Ok(LaunchProgress::AwaitingExecCommit(Box::new(root)))
                }
                Progress::Executed(root, observation) => {
                    let native = s.native()?;
                    let (scope, guarantee, entry) =
                        (native.scope.clone(), native.guarantee, native.entry);
                    let record = ProcessRecord {
                        format_version: 1,
                        lifecycle: s.reservation.lifecycle.clone(),
                        host: self.inner.config.instance,
                        owner: self.inner.owner.clone(),
                        generation: s.generation,
                        root,
                        scope,
                        guarantee,
                        entry,
                        state: LifecycleState::Running,
                        ownership_release: None,
                        exit_status: None,
                        observed_at_unix_ns: now()?,
                        argv_sha256: s.argv_sha256,
                    };
                    s.record = Some(record.clone());
                    s.set_phase(LifecycleState::Running)?;
                    Ok(LaunchProgress::Started(Box::new(LaunchSuccess {
                        process: OwnedProcess {
                            key: ticket.key.clone(),
                        },
                        record,
                        exec_observed: *observation,
                    })))
                }
            }
        });
        match result {
            Ok(progress) => Ok(progress),
            Err(e) => {
                self.inner.apply(&ticket.key, true, |s| {
                    s.failure = Some(e.clone());
                    Ok(())
                })?;
                Ok(LaunchProgress::Failed(Box::new(LaunchFailure {
                    error: e,
                    remaining: Some(OwnedProcess {
                        key: ticket.key.clone(),
                    }),
                    rollback: None,
                })))
            }
        }
    }
    fn authorize_exec(&self, ticket: &LaunchTicket) -> ProcResult<()> {
        self.inner.apply(&ticket.key, false, |s| {
            if s.root_checkpoint.is_none() || s.phase != LifecycleState::Starting {
                return Err(state(
                    &ticket.key.lifecycle,
                    s.phase,
                    "authorize_exec without RootCheckpoint",
                ));
            }
            if Instant::now() >= s.deadline {
                return Err(input("deadline", "exec authorization expired"));
            }
            s.native()?.authorize()
        })
    }
    fn cancel_launch(
        &self,
        ticket: LaunchTicket,
        prepared: PreparedStop,
    ) -> ProcResult<StopAttempt> {
        if ticket.key.lifecycle != prepared.key.lifecycle
            || ticket.key.generation != prepared.key.generation
            || !std::sync::Weak::ptr_eq(&ticket.key.slot, &prepared.key.slot)
        {
            return Err(input(
                "cancel_launch",
                "stop token and launch ticket must identify the same slot/generation",
            ));
        }
        self.request_stop(prepared)
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
            .cloned()
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
        if generation != process.key.generation {
            return Err(error(
                ProcErrorCode::GenerationChanged,
                ProcErrorDetail::Generation {
                    expected: generation,
                    current: process.key.generation,
                },
            ));
        }
        let nonce = self.inner.apply(&process.key, true, |s| {
            if !matches!(
                s.phase,
                LifecycleState::Reserved
                    | LifecycleState::Starting
                    | LifecycleState::Running
                    | LifecycleState::LeaderExited
                    | LifecycleState::StopUnproved
                    | LifecycleState::StopRequested
            ) {
                return Err(state(&process.key.lifecycle, s.phase, "prepare_stop"));
            }
            if deadline <= Instant::now() {
                return Err(token_error(&process.key, true, false));
            }
            s.stop_prepared = s
                .stop_prepared
                .checked_add(1)
                .ok_or_else(|| input("stop token", "counter exhausted"))?;
            Ok(s.stop_prepared)
        })?;
        Ok(PreparedStop {
            key: process.key.clone(),
            deadline,
            nonce,
        })
    }
    fn request_stop(&self, prepared: PreparedStop) -> ProcResult<StopAttempt> {
        let key = prepared.key;
        let (attempt, dispatch) = self.inner.apply(&key, true, |s| {
            s.set_phase(LifecycleState::StopRequested)?;
            s.stop_attempt = s
                .stop_attempt
                .checked_add(1)
                .ok_or_else(|| input("stop attempt", "counter exhausted"))?;
            let dispatch = if prepared.deadline <= Instant::now() {
                Err(token_error(&key, true, false))
            } else if prepared.nonce <= s.stop_consumed || prepared.nonce != s.stop_prepared {
                Err(token_error(&key, false, true))
            } else {
                s.stop_consumed = prepared.nonce;
                match &mut s.native {
                    Some(native) => native.stop(prepared.deadline),
                    None if !s.launched => Ok(()),
                    None => Err(input("stop", "native child custody is unresolved")),
                }
            };
            if let Err(e) = &dispatch {
                s.set_phase(LifecycleState::StopUnproved)?;
                s.failure = Some(e.clone());
            }
            Ok((s.stop_attempt, dispatch))
        })?;
        Ok(StopAttempt {
            ticket: StopTicket { key, attempt },
            dispatch,
        })
    }
    fn witness_stop(&self, ticket: &StopTicket) -> ProcResult<StopObservation> {
        self.inner.apply(&ticket.key, true, |s| {
            if ticket.attempt == 0 || ticket.attempt > s.stop_attempt {
                return Err(input("stop ticket", "unknown attempt"));
            }
            witness(s)
        })
    }
    fn witness_exit(&self, process: &OwnedProcess) -> ProcResult<StopObservation> {
        self.inner.apply(&process.key, true, witness)
    }
    fn release(&self, process: &OwnedProcess, supplied: &StopWitness) -> ProcResult<()> {
        self.inner.apply(&process.key, true, |s| {
            let StopObservation::Complete(current) = witness(s)? else {
                return Err(input("release", "required scope exit is not proved"));
            };
            if supplied.lifecycle != current.lifecycle
                || supplied.scope != current.scope
                || !same_root_custody(&supplied.root, &current.root)
                || supplied.guarantee != current.guarantee
            {
                return Err(input(
                    "exit witness",
                    "witness differs from retained native custody",
                ));
            }
            if let Some(native) = &mut s.native {
                native.release(true)?;
            }
            s.released = true;
            s.hub.disable();
            Ok(())
        })?;
        self.inner.remove(&process.key)
    }
    fn release_uncontained(
        &self,
        process: &OwnedProcess,
        release: &UnwitnessedRelease,
    ) -> ProcResult<ReleasedOwnership> {
        self.inner.apply(&process.key, true, |s| {
            if s.phase != LifecycleState::StopUnproved {
                return Err(state(
                    &process.key.lifecycle,
                    s.phase,
                    "release_uncontained",
                ));
            }
            if release.lifecycle != s.reservation.lifecycle
                || release.generation != s.generation
                || s.native()?.scope != release.scope
                || !matches!(
                    release.scope,
                    ScopeIdentity::LinuxTracked { .. } | ScopeIdentity::MacOsTracked { .. }
                )
            {
                return Err(input(
                    "release",
                    "exact tracked lifecycle, generation and scope required",
                ));
            }
            // Host has committed its human-only CAS and drained dispatch. Native
            // retirement sends no signal and never constructs an exit witness.
            s.native()?.release(false)?;
            s.released = true;
            s.hub.disable();
            if let Some(record) = &mut s.record {
                record.ownership_release = Some(release.clone());
            }
            Ok(())
        })?;
        self.inner.remove(&process.key)?;
        Ok(ReleasedOwnership {
            release: release.clone(),
        })
    }
    fn plan_recovery(&self, source: RecoverySource) -> ProcResult<RecoveryPlan> {
        super::recovery::plan(self, source)
    }
    fn recover(&self, plan: RecoveryPlan, generation: GenerationId) -> ProcResult<RecoveryOutcome> {
        super::recovery::recover(self, plan, generation)
    }
}
fn token_error(key: &super::Reference, expired: bool, consumed: bool) -> ProcError {
    error(
        if expired {
            ProcErrorCode::StopTokenExpired
        } else {
            ProcErrorCode::StopTokenConsumed
        },
        ProcErrorDetail::Token {
            lifecycle: key.lifecycle.clone(),
            expired,
            consumed,
        },
    )
}
fn same_root_custody(a: &RootWitness, b: &RootWitness) -> bool {
    match (a, b) {
        (RootWitness::NoChildCreated, RootWitness::NoChildCreated) => true,
        (
            RootWitness::Identified { expected: a, .. },
            RootWitness::Identified { expected: b, .. },
        ) => a == b,
        (
            RootWitness::PinnedUnpublished { pid: a, .. },
            RootWitness::PinnedUnpublished { pid: b, .. },
        ) => a == b,
        _ => false,
    }
}
pub(super) fn witness(s: &mut Slot) -> ProcResult<StopObservation> {
    if s.native.is_none() && !s.launched {
        // Failed preparation cannot have created a vendor. Query the exact
        // vendor-free reservation outside the failed writer before retiring it.
        let (scope_exit, guarantee) = crate::platform::uncreated_scope(&s.reservation)?;
        s.set_phase(LifecycleState::Exited)?;
        return Ok(StopObservation::Complete(Box::new(StopWitness {
            lifecycle: s.reservation.lifecycle.clone(),
            root: RootWitness::NoChildCreated,
            scope: scope_exit.scope.clone(),
            scope_exit,
            guarantee,
            observed_at_unix_ns: now()?,
        })));
    }
    let mut root = match s.native()?.root() {
        Ok(root) => root,
        Err(cause)
            if cfg!(target_os = "linux")
                && cause.code == ProcErrorCode::IdentityUnreadable
                && cause
                    .native
                    .as_ref()
                    .is_some_and(|native| native.code == Some(2)) =>
        {
            return Ok(StopObservation::Pending {
                root: None,
                scope: Box::new(ScopeObservation {
                    scope: s.native()?.scope.clone(),
                    remaining: RemainingScope {
                        population: Population::Unknown,
                        known_live: Vec::new(),
                        extent: EnumerationExtent::Partial {
                            reason: format!("native root exit remains unreadable: {cause:?}"),
                            omitted: None,
                        },
                        observed_at_unix_ns: now()?,
                    },
                    exit_basis: None,
                }),
            });
        }
        Err(cause) => return Err(cause),
    };
    let root_ready = !matches!(root, Some(ProcessObservation::Exited { .. }))
        || s.native()?.root_exit_ready()?;
    if root_ready && matches!(root, Some(ProcessObservation::Exited { .. })) {
        // A pending waitid may have just become readable above. Return its
        // retained status now, before constructing a complete witness.
        root = s.native()?.root()?;
    }
    let scope = s.native()?.observe()?;
    if let Some(ProcessObservation::Exited { status, .. }) = &root
        && let Some(record) = &mut s.record
    {
        record.exit_status = Some(status.clone());
    }
    let root_witness = match &root {
        Some(ProcessObservation::Exited {
            expected,
            evidence,
            status,
            ..
        }) => Some(RootWitness::Identified {
            expected: expected.clone(),
            evidence: Box::new(evidence.clone()),
            status: status.clone(),
        }),
        Some(ProcessObservation::Live(_)) => None,
        None if !s.native()?.child_created() => Some(RootWitness::NoChildCreated),
        None => s
            .native()?
            .unpublished_exit()?
            .map(|(pid, status)| RootWitness::PinnedUnpublished { pid, status }),
    };
    if root_ready
        && scope.remaining.population == Population::Empty
        && scope.exit_basis.is_some()
        && let Some(root) = root_witness
    {
        let witness = Box::new(StopWitness {
            lifecycle: s.reservation.lifecycle.clone(),
            root,
            scope: scope.scope.clone(),
            scope_exit: scope.clone(),
            observed_at_unix_ns: now()?,
            guarantee: s.native()?.guarantee,
        });
        let bounded = !matches!(scope.remaining.extent, EnumerationExtent::Complete);
        s.set_phase(if bounded {
            LifecycleState::StopUnproved
        } else {
            LifecycleState::Exited
        })?;
        return Ok(if bounded {
            StopObservation::Bounded(witness)
        } else {
            StopObservation::Complete(witness)
        });
    }
    if matches!(s.phase, LifecycleState::StopRequested) {
        s.set_phase(LifecycleState::StopUnproved)?;
    }
    Ok(StopObservation::Pending {
        root: root.map(Box::new),
        scope: Box::new(scope),
    })
}
