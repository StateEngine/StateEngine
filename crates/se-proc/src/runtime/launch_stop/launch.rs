//! Native launch preparation and exec/readiness observation.
use super::*;

impl NativeProcessRuntime {
    pub(super) fn native_prepare_launch(
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
        let stdio_bound = spec.stdio.stdin.is_some()
            || spec.stdio.stdout.is_some()
            || spec.stdio.stderr.is_some();
        let slot = Arc::new(Mutex::new(Slot {
            reservation: reservation.clone(),
            checkpoint: None,
            root_checkpoint: None,
            record: None,
            native: None,
            spec: Some(spec),
            stdio_bound,
            #[cfg(windows)]
            stdio: None,
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
                    "native lifecycle entries",
                    self.inner.config.limits.max_lifecycles as u64,
                ));
            }
            slots.insert(lifecycle.clone(), SlotEntry::Owned(slot.clone()));
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
                argv_sha256: digest,
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
    pub(super) fn native_bind_stdio(
        &self,
        prepared: &PreparedLaunch,
        child: StandardIo,
    ) -> ProcResult<()> {
        let key = &prepared.key;
        self.inner.apply(key, false, |slot| {
            if slot.launched || slot.phase != LifecycleState::Starting {
                return Err(state(&key.lifecycle, slot.phase, "bind_stdio"));
            }
            let result = (|| {
                if let Some(failure) = &slot.failure {
                    return Err(failure.clone());
                }
                if Instant::now() >= slot.deadline {
                    return Err(error(
                        ProcErrorCode::LaunchTimedOut,
                        ProcErrorDetail::Input {
                            field: "deadline".into(),
                            reason: "launch deadline elapsed before stream binding".into(),
                        },
                    ));
                }
                if slot.stdio_bound {
                    return Err(input(
                        "stdio",
                        "prepared launch already owns stream bindings",
                    ));
                }
                let spec = slot
                    .spec
                    .as_mut()
                    .ok_or_else(|| input("stdio", "prepared launch spec is unavailable"))?;
                if spec.mode != LaunchMode::Headless
                    && !matches!(
                        spec.window,
                        Some(WindowSpec::UnixTerminalWithBackend { .. })
                    )
                {
                    return Err(input(
                        "stdio",
                        "provider stream binding requires headless mode",
                    ));
                }
                spec.stdio = child;
                slot.stdio_bound = true;
                Ok(())
            })();
            if let Err(failure) = &result {
                slot.failure = Some(failure.clone());
            }
            result
        })
    }
    pub(super) fn native_begin_launch(&self, prepared: PreparedLaunch) -> LaunchStart {
        let key = prepared.key;
        let result = self.inner.apply(&key, false, |s| {
            if s.launched || s.phase != LifecycleState::Starting {
                return Err(state(&key.lifecycle, s.phase, "begin_launch"));
            }
            if let Some(failure) = &s.failure {
                return Err(failure.clone());
            }
            #[cfg(windows)]
            if let Some(stdio) = &s.stdio {
                if !s.stdio_bound {
                    return Err(input(
                        "stdio",
                        "created provider streams must bind before vendor execution",
                    ));
                }
                stdio.launch_ready()?;
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
    pub(super) fn native_poll_launch(&self, ticket: &LaunchTicket) -> ProcResult<LaunchProgress> {
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
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                Progress::Pending => Ok(LaunchProgress::Pending),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    pub(super) fn native_authorize_exec(&self, ticket: &LaunchTicket) -> ProcResult<()> {
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
    pub(super) fn native_cancel_launch(
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
}
