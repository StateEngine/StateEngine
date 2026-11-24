//! Reuse the process arena's preparation, exec and exit barriers for auxiliary
//! processes. Every returned reference is retained before another await.
use super::*;
use se_proc::{
    CheckpointKind, CheckpointSource, LaunchProgress, LaunchStart, ProcessRuntime, RecoverySource,
    StartIdentity as NativeStart, StopObservation,
};
use se_types::StartIdentity as StoredStart;
use std::ffi::OsString;

pub(super) async fn sleep_poll_interval(deadline: &Deadline) -> Result<()> {
    tokio::time::sleep(
        deadline
            .remaining()?
            .min(std::time::Duration::from_millis(25)),
    )
    .await;
    Ok(())
}

impl LaunchCoordinator {
    pub(super) async fn run_blocking<T: Send + 'static>(
        &self,
        deadline: &Deadline,
        op: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.store.pool.run_owned(deadline, op).await
    }
    pub(super) async fn run_native<T: Send + 'static>(
        &self,
        deadline: &Deadline,
        op: impl FnOnce(&NativeProcessRuntime) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let native = self.native.clone();
        self.run_blocking(deadline, move || op(&native)).await
    }
    pub(super) async fn observe_secode_birth(
        &self,
        service: &Service,
        deadline: &Deadline,
    ) -> Result<u32> {
        if let Some(restart) = &service.restart {
            let expected = restart.identity.clone();
            if expected.boot != self.options.epoch.owner.fields().boot {
                return Err(error(
                    "SE Code restarted service",
                    "the replacement belongs to an earlier system boot",
                ));
            }
            let machine = self.owner.machine.clone();
            return self
                .run_blocking(deadline, move || {
                    let pid = se_proc::ProcessId(expected.pid.get());
                    let observed = se_proc::read_process(machine, pid)
                        .map_err(|failure| error("SE Code restarted service", failure))?;
                    let se_proc::ProcessRead::Present(observed) = observed else {
                        return Err(error(
                            "SE Code restarted service",
                            "the observed replacement process is no longer present",
                        ));
                    };
                    let matches = match (&observed.identity.start, &expected.started) {
                        (
                            NativeStart::Linux { start_ticks: a },
                            StoredStart::Linux { start_ticks: b },
                        ) => a == b,
                        (
                            NativeStart::Windows {
                                creation_filetime: a,
                            },
                            StoredStart::Windows {
                                creation_filetime: b,
                            },
                        ) => *a == b.get(),
                        (
                            NativeStart::MacOs {
                                seconds: a,
                                microseconds: a_us,
                            },
                            StoredStart::Macos {
                                start_seconds: b,
                                start_micros: b_us,
                            },
                        ) => a == b && a_us == b_us,
                        _ => false,
                    };
                    if !matches || observed.state != se_proc::NativeState::Running {
                        return Err(error(
                            "SE Code restarted service",
                            "the original replacement process is no longer running",
                        ));
                    }
                    Ok(pid.0)
                })
                .await;
        }
        let pid = match service
            .journal
            .service
            .as_ref()
            .map(|checkpoint| &checkpoint.checkpoint)
        {
            Some(CheckpointKind::Process(record)) => record.root.pid.0,
            _ => {
                return Err(error(
                    "SE Code native custody",
                    "original service process is not retained",
                ));
            }
        };
        let owner = service
            .process
            .clone()
            .ok_or_else(|| error("SE Code native custody", "original service owner is absent"))?;
        self.run_native(deadline, move |native| {
            let observed = native
                .observe(&owner)
                .map_err(|failure| error("SE Code native custody", failure))?;
            if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
                return Err(error(
                    "SE Code native custody",
                    "original native service is not live",
                ));
            }
            Ok(pid)
        })
        .await
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "one native launch with distinct custody and policy coordinates"
    )]
    pub(super) async fn start_secode_auxiliary(
        &self,
        service: &mut Service,
        auxiliary: Auxiliary,
        executable: se_proc::NativeExecutableInvocation,
        arguments: Vec<OsString>,
        cwd: PathBuf,
        policy: se_proc::LaunchPolicy,
        input: Option<se_types::Secret>,
        deadline: &Deadline,
    ) -> Result<se_proc::ProcessRecord> {
        let reservation = self
            .reserve_secode_auxiliary(service, auxiliary, deadline)
            .await?;
        let environment = self
            .secode_auxiliary_environment(service, auxiliary, deadline)
            .await?;
        let image_path = executable.original_path().to_owned();
        let spec = se_proc::LaunchSpec {
            executable_custody: Some(executable),
            lifecycle: reservation.lifecycle.clone(),
            generation: self.options.epoch.generation,
            executable: image_path,
            arguments,
            cwd,
            environment: se_proc::Environment {
                entries: environment,
            },
            stdio: se_proc::StandardIo {
                stdin: None,
                stdout: None,
                stderr: None,
            },
            mode: se_proc::LaunchMode::HeadlessConsole,
            window: None,
            policy,
            deadline: deadline.at(),
            notifications: service.wake.clone(),
        };
        let prepared = self
            .run_native(deadline, move |native| {
                native
                    .prepare_launch(reservation, spec)
                    .map_err(super::super::prepare_error)
            })
            .await?;
        *service.owner_mut(auxiliary) = Some(Arc::new(prepared.process));
        service.checkpoint(auxiliary, CheckpointKind::Scope(prepared.checkpoint))?;
        service.persist(self, deadline).await?;
        let prepared = self
            .bind_secode_auxiliary_stdio(service, auxiliary, prepared.prepared, input, deadline)
            .await?;
        let ticket = self
            .run_native(deadline, move |native| {
                match native.begin_launch(prepared) {
                    LaunchStart::Pending { ticket, .. } => Ok(ticket),
                    LaunchStart::Failed(failure) => {
                        Err(error("SE Code auxiliary launch", failure.error))
                    }
                }
            })
            .await?;
        self.await_secode_auxiliary_launch(service, auxiliary, ticket, deadline)
            .await
    }
    async fn reserve_secode_auxiliary(
        &self,
        service: &mut Service,
        auxiliary: Auxiliary,
        deadline: &Deadline,
    ) -> Result<se_proc::LaunchReservation> {
        if service.journal.auxiliary(auxiliary).is_some() {
            return Err(error(
                "SE Code auxiliary retry",
                "reconcile the original native checkpoint before creating another process",
            ));
        }
        let mut bytes = [0; 10];
        se_proc::fill_entropy(&mut bytes).map_err(|e| error("SE Code lifecycle entropy", e))?;
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| error("SE Code launch clock", e))?;
        let lifecycle = se_types::LifecycleId::from_parts(created_at.as_millis() as u64, bytes)?;
        let mut nonce = [0; 16];
        se_proc::fill_entropy(&mut nonce).map_err(|e| error("SE Code scope entropy", e))?;
        let reservation = se_proc::LaunchReservation {
            format_version: 1,
            lifecycle,
            host: self.host,
            owner: self.owner.clone(),
            generation: self.options.epoch.generation,
            scope_nonce: nonce,
            parent: if cfg!(windows) {
                se_proc::ReservationParent::Windows
            } else if cfg!(target_os = "macos") {
                se_proc::ReservationParent::MacOs
            } else {
                se_proc::ReservationParent::LinuxTracked
            },
            created_at_unix_ns: created_at.as_nanos(),
        };
        service.checkpoint(auxiliary, CheckpointKind::Reservation(reservation.clone()))?;
        service.persist(self, deadline).await?;
        Ok(reservation)
    }
    async fn secode_auxiliary_environment(
        &self,
        service: &Service,
        auxiliary: Auxiliary,
        deadline: &Deadline,
    ) -> Result<Vec<(OsString, OsString)>> {
        let mut environment = crate::harness::secode_process::provider_environment();
        let scratch = service
            .journal
            .profile
            .to_local()?
            .with_extension("scratch");
        let private_scratch = scratch.clone();
        self.run_blocking(deadline, move || {
            se_proc::NativeStateFiles::create(&private_scratch)
                .map(|_| ())
                .map_err(|e| error("SE Code private temporary directory", e))
        })
        .await?;
        environment.retain(|(key, _)| {
            !key.to_str().is_some_and(|key| {
                ["TMPDIR", "TMP", "TEMP"]
                    .iter()
                    .any(|name| key.eq_ignore_ascii_case(name))
            })
        });
        for name in ["TMPDIR", "TMP", "TEMP"] {
            environment.push((name.into(), scratch.as_os_str().to_owned()));
        }
        if auxiliary == Auxiliary::Service {
            environment.push((
                "SECODE_CONFIG".into(),
                service
                    .journal
                    .profile
                    .to_local()?
                    .join("host-policy.json")
                    .into_os_string(),
            ));
        }
        Ok(environment)
    }
    async fn bind_secode_auxiliary_stdio(
        &self,
        service: &mut Service,
        auxiliary: Auxiliary,
        prepared: se_proc::PreparedLaunch,
        input: Option<se_types::Secret>,
        deadline: &Deadline,
    ) -> Result<se_proc::PreparedLaunch> {
        let owner = service
            .owner(auxiliary)
            .clone()
            .ok_or_else(|| error("SE Code auxiliary streams", "native reference absent"))?;
        let io = self.io.clone();
        let identity = crate::SessionIdentity {
            project: service.journal.project.clone(),
            agent: service.journal.agent.clone(),
            session: service.journal.session.clone(),
        };
        let runtime = self.store.pool.handle();
        let streams = self
            .run_blocking(deadline, move || {
                let _entered = runtime.enter();
                io.open(&owner, &identity)
            })
            .await?;
        let prepared = self
            .run_native(deadline, move |native| {
                native
                    .bind_stdio(&prepared, streams.child)
                    .map_err(|e| error("SE Code auxiliary stream binding", e))?;
                Ok(prepared)
            })
            .await?;
        let output = diagnostic::Output::new(
            self.io.clone(),
            streams.host,
            self.store.generation,
            self.options.home.join("secode-diagnostics").join(format!(
                "{}.json",
                service.journal.checkpoint_lifecycle(auxiliary)?
            )),
        );
        *service.output_mut(auxiliary) = Some(output.clone());
        output.start().await;
        if let Some(input) = input {
            output.write_input(&input, deadline).await?;
        }
        output.finish_input(deadline).await?;
        Ok(prepared)
    }
    async fn await_secode_auxiliary_launch(
        &self,
        service: &mut Service,
        auxiliary: Auxiliary,
        mut ticket: se_proc::LaunchTicket,
        deadline: &Deadline,
    ) -> Result<se_proc::ProcessRecord> {
        loop {
            let (returned, progress) = self
                .run_native(deadline, move |native| {
                    let progress = native
                        .poll_launch(&ticket)
                        .map_err(|e| error("SE Code auxiliary progress", e))?;
                    Ok((ticket, progress))
                })
                .await?;
            ticket = returned;
            match progress {
                LaunchProgress::AwaitingExecCommit(root) => {
                    service.checkpoint(auxiliary, CheckpointKind::Root(*root))?;
                    service.persist(self, deadline).await?;
                    ticket = self
                        .run_native(deadline, move |native| {
                            native
                                .authorize_exec(&ticket)
                                .map_err(|e| error("SE Code auxiliary exec", e))?;
                            Ok(ticket)
                        })
                        .await?;
                }
                LaunchProgress::Started(success) => {
                    service
                        .checkpoint(auxiliary, CheckpointKind::Process(success.record.clone()))?;
                    service.persist(self, deadline).await?;
                    return Ok(success.record);
                }
                LaunchProgress::Failed(failure) => {
                    return Err(error("SE Code auxiliary launch", failure.error));
                }
                LaunchProgress::Pending => {
                    super::super::launch_util::wait(&service.wake, deadline).await?
                }
            }
        }
    }
    /// Interrupt is a native dispatch, never a closure claim. Force, if needed,
    /// is recorded by the caller separately from graceful cancellation.
    pub(super) async fn stop_secode_auxiliary(
        &self,
        service: &mut Service,
        auxiliary: Auxiliary,
        force: bool,
        deadline: &Deadline,
    ) -> Result<se_proc::StopWitness> {
        let owner = service
            .owner(auxiliary)
            .clone()
            .ok_or_else(|| error("SE Code auxiliary stop", "retained native reference absent"))?;
        let process = owner.clone();
        let observed = self
            .run_native(deadline, move |native| {
                native
                    .witness_exit(&process)
                    .map_err(|e| error("SE Code auxiliary exit", e))
            })
            .await?;
        if let StopObservation::Complete(witness) = observed {
            self.retire_secode_auxiliary(service, auxiliary, &witness, deadline)
                .await?;
            return Ok(*witness);
        }
        let generation = self.options.epoch.generation;
        let at = deadline.at();
        let mut attempt = self
            .run_native(deadline, move |native| {
                let prepared = native
                    .prepare_stop(&owner, generation, at)
                    .map_err(|e| error("SE Code auxiliary stop preparation", e))?;
                if force {
                    native.request_stop(prepared)
                } else {
                    native.request_interrupt(prepared)
                }
                .map_err(|e| error("SE Code auxiliary cancellation", e))
            })
            .await?;
        attempt
            .dispatch
            .map_err(|e| error("SE Code auxiliary dispatch", e))?;
        loop {
            let (ticket, observed) = self
                .run_native(deadline, move |native| {
                    let observed = native
                        .witness_stop(&attempt.ticket)
                        .map_err(|e| error("SE Code auxiliary exit", e))?;
                    Ok((attempt.ticket, observed))
                })
                .await?;
            if let StopObservation::Complete(witness) = observed {
                self.retire_secode_auxiliary(service, auxiliary, &witness, deadline)
                    .await?;
                return Ok(*witness);
            }
            attempt = se_proc::StopAttempt {
                ticket,
                dispatch: Ok(se_proc::StopDispatch::Requested),
            };
            // Recovered auxiliaries have no original child wait subscription.
            // Re-observe their exact retained stop ticket within this explicit
            // cancellation window instead of waiting for a lost parent wake.
            sleep_poll_interval(deadline).await?;
        }
    }
    pub(super) async fn retire_secode_auxiliary(
        &self,
        service: &mut Service,
        auxiliary: Auxiliary,
        witness: &se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        self.drain_secode_auxiliary(service, auxiliary, deadline)
            .await?;
        let checkpoint = service
            .journal
            .auxiliary(auxiliary)
            .as_ref()
            .ok_or_else(|| error("SE Code auxiliary retirement", "checkpoint absent"))?;
        let source = if let CheckpointKind::Exit {
            source,
            witness: original,
        } = &checkpoint.checkpoint
        {
            if original.lifecycle != witness.lifecycle || original.scope != witness.scope {
                return Err(error(
                    "SE Code auxiliary release retry",
                    "fresh exit differs from original retained scope",
                ));
            }
            (**source).clone()
        } else {
            match custody::source(checkpoint)? {
                RecoverySource::Reservation(v) => CheckpointSource::Reservation(*v),
                RecoverySource::Prepared(v) => CheckpointSource::Scope(*v),
                RecoverySource::RootPrepared(v) => CheckpointSource::Root(*v),
                RecoverySource::Record(v) => CheckpointSource::Process(*v),
            }
        };
        service.checkpoint(
            auxiliary,
            CheckpointKind::Exit {
                source: Box::new(source),
                witness: witness.clone(),
            },
        )?;
        service.persist(self, deadline).await?;
        let owner = service
            .owner(auxiliary)
            .clone()
            .ok_or_else(|| error("SE Code auxiliary release", "native reference absent"))?;
        let copied = witness.clone();
        self.run_native(deadline, move |native| {
            native
                .release(&owner, &copied)
                .map_err(|e| error("SE Code auxiliary release", e))
        })
        .await?;
        *service.owner_mut(auxiliary) = None;
        Ok(())
    }
    pub(super) async fn drain_secode_auxiliary(
        &self,
        service: &Service,
        auxiliary: Auxiliary,
        deadline: &Deadline,
    ) -> Result<()> {
        let output = service.output(auxiliary).clone();
        if let Some(output) = output {
            output.close(deadline).await?;
            let save_deadline = deadline.clone();
            self.run_blocking(deadline, move || output.save(&save_deadline))
                .await?;
        }
        Ok(())
    }
}
