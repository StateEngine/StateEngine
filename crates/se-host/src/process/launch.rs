//! Ordered launch barriers and real provider readiness. The supervisor retains
//! every intermediate native reference and file digest through failures.
use super::launch_util::{call, policy, resolve_provider_launch, token, wait};
use super::*;
use crate::{
    ConfigPlan, HarnessRequest, ProbeRequest, ProviderInvocation, ProviderTransport,
    SessionIdentity, client::lease::Deadline,
};
use se_core::ops::{LaunchResult, agent_launch::LaunchPlan, process_commit};
use se_core::scope::unreadable;
use se_proc::{
    CheckpointKind, LaunchMode, LaunchProgress, LaunchReservation, LaunchSpec, LaunchStart,
    LaunchTicket, OwnedProcess, PreparedLaunch, ProcessRecord, ProcessRuntime, ReservationParent,
    StandardIo,
};
use se_store::{EventBody, ProcessState, ProjectionRecord, Snapshot};
use se_types::{Body, BootId, Detail, Result, SeError};
use sha2::{Digest, Sha256};

pub(super) use super::owned::Work;
/// What a launch would refuse before any native effect, checked by a forced
/// relaunch before it stops the live agent.
pub(super) struct Qualified {
    pub command: super::launch_util::ProviderExecutable,
    pub window: Option<se_proc::WindowSpec>,
    pub mode: se_proc::LaunchMode,
    pub policy: se_proc::LaunchPolicy,
}
/// Proof that a new launch is choosing a Codex login. Its private field means
/// only this file can make one, so no later reader can consult the host.
pub(super) struct NewLaunch(());

fn empty_stdio() -> StandardIo {
    StandardIo {
        stdin: None,
        stdout: None,
        stderr: None,
    }
}
struct LaunchHashes {
    session: [u8; 32],
    http: [u8; 32],
}
struct PreparedScope {
    owner: Arc<OwnedProcess>,
    prepared: PreparedLaunch,
    argv_sha256: [u8; 32],
    provider_pipes: bool,
}
struct LaunchMaterial {
    request: HarnessRequest,
    configuration: ConfigPlan,
    hashes: LaunchHashes,
}

impl LaunchCoordinator {
    pub(super) fn boot(&self) -> &BootId {
        &self.options.epoch.owner.fields().boot
    }
    async fn prepare_invocation(
        &self,
        plan: &LaunchPlan,
        harness: &dyn crate::Harness,
        qualified: &mut Qualified,
        request: &HarnessRequest,
        #[cfg(unix)] alias_parent: bool,
        deadline: &Deadline,
    ) -> Result<(ConfigPlan, ProviderInvocation)> {
        let provider = plan.details().provider;
        let mut configuration = harness
            .configuration(request, call(self.store.generation, deadline)?)
            .await?;
        // A new launch is the one place a Codex agent's login is chosen; it is
        // recorded for the agent's life and every later reader uses the record.
        let codex_login = if provider == se_types::Provider::Codex {
            let login = super::codex_server::launch_login(&NewLaunch(()))?;
            configuration
                .ephemeral_files
                .push(self.codex.login_record(&request.identity.session, &login)?);
            Some(login)
        } else {
            None
        };
        let mut invocation = harness
            .invocation(request, call(self.store.generation, deadline)?)
            .await?;
        super::launch_util::route_temporary_files(&mut invocation.environment, &qualified.policy);
        // A Codex agent's own process is a forwarder; the Codex executable, its
        // package environment and any alias supervisor belong to the login's
        // shared server instead.
        if provider == se_types::Provider::Codex {
            let login = codex_login
                .ok_or_else(|| error("Codex launch", "the login chosen for this launch"))?;
            invocation
                .arguments
                .push(crate::harness::codex_input::control_socket(&login).into_os_string());
            let settings = self.codex.server_settings(request, &login)?;
            let windows_sandbox = settings.windows_sandbox;
            let mut server = ProviderInvocation {
                executable: request.executable.clone(),
                arguments: Vec::new(),
                environment: se_proc::Environment {
                    entries: settings.environment,
                },
            };
            if let Some(package) = qualified.command.package.take() {
                package
                    .apply(&mut server.environment)
                    .map_err(|e| error("Codex package environment", e))?;
            }
            #[cfg(unix)]
            {
                server = self
                    .on_pool(deadline, move || {
                        super::launch_util::stabilize_alias(server, alias_parent)
                    })
                    .await?;
            }
            let launch = super::codex_server::ServerLaunch {
                executable: server.executable.to_local()?,
                prefix: server.arguments,
                environment: server.environment.entries,
                windows_sandbox,
            };
            if let Some(verified) = self
                .ensure_codex_server(login, launch, &plan.lifecycle, deadline)
                .await?
            {
                invocation
                    .arguments
                    .push(format!("--expected-peer-pid={}", verified.pid.0).into());
                if let se_proc::StartIdentity::Windows { creation_filetime } = verified.start {
                    invocation
                        .arguments
                        .push(format!("--expected-peer-birth={creation_filetime}").into());
                }
            }
        } else {
            #[cfg(unix)]
            {
                invocation = self
                    .on_pool(deadline, move || {
                        super::launch_util::stabilize_alias(invocation, alias_parent)
                    })
                    .await?;
            }
        }
        if qualified.mode == LaunchMode::Window && cfg!(target_os = "linux") {
            invocation.environment.entries.retain(|(k, _)| k != "TERM");
            invocation
                .environment
                .entries
                .push(("TERM".into(), "xterm-256color".into()));
        }
        Ok((configuration, invocation))
    }

    async fn commit_reservation(
        &self,
        work: &mut Work,
        plan: &LaunchPlan,
        hashes: &LaunchHashes,
        deadline: &Deadline,
    ) -> Result<LaunchReservation> {
        let mut nonce = [0; 16];
        se_proc::fill_entropy(&mut nonce).map_err(|e| error("launch scope entropy", e))?;
        let reservation = LaunchReservation {
            format_version: 1,
            lifecycle: plan.lifecycle.clone(),
            host: self.host,
            owner: self.owner.clone(),
            generation: self.options.epoch.generation,
            scope_nonce: nonce,
            parent: if cfg!(windows) {
                ReservationParent::Windows
            } else if cfg!(target_os = "macos") {
                ReservationParent::MacOs
            } else {
                ReservationParent::LinuxTracked
            },
            created_at_unix_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| error("launch clock", e))?
                .as_nanos(),
        };
        work.reservation = Some(reservation.clone());
        let stored = native_record::identity(
            plan,
            CheckpointKind::Reservation(reservation.clone()),
            None,
            None,
            self.boot(),
        )?;
        let (saved, session_hash, http_hash) = (plan.clone(), hashes.session, hashes.http);
        let reserve =
            move |k: &se_core::dispatch::Kernel,
                  cx: &mut se_core::commit::Cx<'_, se_store::SqliteSnapshot>| {
                process_commit::reserve(k, &saved, stored, session_hash, http_hash, cx)
            };
        let (admission, seed) = (work.admission.clone(), Some(plan.seed.clone()));
        #[cfg(feature = "remote")]
        let reserved = match work.remote_permit.take() {
            Some(permit) => {
                self.store
                    .commit_remote(admission, deadline, seed, permit, reserve)
                    .await
            }
            None => self.store.commit(admission, deadline, seed, reserve).await,
        };
        #[cfg(not(feature = "remote"))]
        let reserved = self.store.commit(admission, deadline, seed, reserve).await;
        if let Err(failure) = reserved {
            work.reservation_uncertain = matches!(
                failure.body.detail(),
                Detail::CommitOutcomeUnknown(_) | Detail::CommittedResponseUnavailable(_)
            );
            return Err(failure);
        }
        work.committed = true;
        Ok(reservation)
    }

    async fn prepare_native_scope(
        &self,
        work: &mut Work,
        plan: &LaunchPlan,
        invocation: ProviderInvocation,
        qualified: Qualified,
        reservation: LaunchReservation,
        deadline: &Deadline,
    ) -> Result<PreparedScope> {
        // Retain native custody before fallible file/service preparation. The
        // original owner must be able to prove no exec and finish its cleanup.
        let executable_custody = if plan.details().provider == se_types::Provider::SeCode {
            let images = self.secode.images(&qualified.command.executable)?;
            Some(
                self.on_pool(deadline, move || {
                    images
                        .lock()
                        .map_err(|_| error("SE Code client image", "poisoned custody"))?
                        .cli_invocation()
                })
                .await?,
            )
        } else {
            None
        };
        let provider_pipes =
            qualified.mode.is_headless() || plan.profile.provider == se_store::Provider::Codex;
        let spec = LaunchSpec {
            executable_custody,
            lifecycle: plan.lifecycle.clone(),
            generation: self.options.epoch.generation,
            executable: invocation.executable.to_local()?,
            arguments: invocation.arguments,
            cwd: plan.cwd.to_local()?,
            environment: invocation.environment,
            stdio: empty_stdio(),
            mode: qualified.mode,
            window: qualified.window,
            policy: qualified.policy,
            deadline: deadline.at(),
            notifications: work.wake.clone(),
        };
        let native = self.native.clone();
        let prepared = self
            .on_pool(deadline, move || {
                native
                    .prepare_launch(reservation, spec)
                    .map_err(super::prepare_error)
            })
            .await?;
        let owner = Arc::new(prepared.process);
        work.process = Some(owner.clone());
        let stored = native_record::identity(
            plan,
            CheckpointKind::Scope(prepared.checkpoint.clone()),
            None,
            Some(prepared.checkpoint.guarantee),
            self.boot(),
        )?;
        self.change(
            work,
            "scope-prepared",
            stored,
            (ProcessState::Reserved, ProcessState::Starting),
            deadline,
        )
        .await?;
        Ok(PreparedScope {
            owner,
            prepared: prepared.prepared,
            argv_sha256: prepared.argv_sha256,
            provider_pipes,
        })
    }

    async fn publish_and_begin_launch(
        &self,
        work: &mut Work,
        plan: &LaunchPlan,
        material: LaunchMaterial,
        scope: PreparedScope,
        deadline: &Deadline,
    ) -> Result<(HarnessRequest, LaunchTicket, ProviderTransport, [u8; 32])> {
        let LaunchMaterial {
            request,
            configuration,
            hashes,
        } = material;
        let provider_pipes = scope.provider_pipes;
        let harness = self.harness_for(plan.profile.provider)?;
        self.proofs.register(
            plan.session.clone(),
            self.store.generation.get(),
            hashes.session,
            hashes.http,
        )?;
        (work.pin_hash, work.pin_file_hash) = (Some(hashes.session), Some(hashes.session));
        work.files = configuration
            .ephemeral_files
            .iter()
            .map(|i| {
                Ok((
                    i.path.to_local()?,
                    Sha256::digest(i.contents.expose()).into(),
                ))
            })
            .collect::<Result<_>>()?;
        let manifest = files::manifest(&self.options.home, plan, hashes.session, &configuration)?;
        work.files
            .push((manifest.0.clone(), Sha256::digest(&manifest.1).into()));
        let (home, session) = (self.options.home.clone(), plan.session.clone());
        let request = self
            .on_pool(deadline, move || {
                files::publish(
                    &home,
                    &session,
                    &request.launch_credential,
                    configuration,
                    manifest,
                )?;
                Ok(request)
            })
            .await?;
        harness
            .prepare(&request, call(self.store.generation, deadline)?)
            .await?;
        if plan.profile.provider == se_store::Provider::SeCode {
            let images = self.secode.images(&request.executable.to_local()?)?;
            let prepared = self
                .prepare_secode(work, &request, images, deadline)
                .await?;
            self.secode.register(&plan.session, prepared)?;
            self.secode_input_intent(&request.identity, deadline)
                .await?;
        }
        let (io, identity, runtime, owner) = (
            self.io.clone(),
            request.identity.clone(),
            self.store.pool.handle(),
            scope.owner,
        );
        let io = if !provider_pipes {
            crate::ProviderIo {
                child: empty_stdio(),
                host: ProviderTransport::console(),
            }
        } else {
            self.on_pool(deadline, move || {
                let _entered = runtime.enter();
                io.open(&owner, &identity)
            })
            .await?
        };
        // Retain cleanup custody before a native creation or readiness failure
        // can drop the transport that the harness has not accepted yet.
        if provider_pipes {
            work.pending_transport = Some(io.host.clone());
        }
        let native = self.native.clone();
        let (ticket, transport, argv) = self
            .on_pool(deadline, move || {
                if provider_pipes {
                    native
                        .bind_stdio(&scope.prepared, io.child)
                        .map_err(|e| error("provider stream binding", e))?;
                }
                match native.begin_launch(scope.prepared) {
                    LaunchStart::Pending { ticket, .. } => Ok((ticket, io.host, scope.argv_sha256)),
                    LaunchStart::Failed(failure) => Err(error("native launch", failure.error)),
                }
            })
            .await?;
        Ok((request, ticket, transport, argv))
    }

    pub(super) async fn start(
        &self,
        work: &mut Work,
        launch_guard: &mut Option<tokio::sync::OwnedMutexGuard<()>>,
        deadline: &Deadline,
    ) -> Result<LaunchResult> {
        work.startup_timing = (work.meta.provider == se_store::Provider::Codex)
            .then(|| crate::startup_timing::Timing::new(&work.meta.conversation));
        let plan = work.plan.clone().ok_or_else(|| {
            unreadable(
                "launch execution",
                "a recovered lifecycle cannot create another provider",
            )
        })?;
        let harness = self.harness_for(plan.profile.provider)?;
        if !plan.control.processes.is_empty()
            || plan
                .control
                .sessions
                .iter()
                .any(|s| !matches!(s.current.body, EventBody::SessionPrepared { .. }))
        {
            return Err(SeError::invalid(
                "launch target state",
                "stop or reconcile the target's existing live preparation before a new launch",
            ));
        }
        // A cold retry is never allowed to allocate another native child over a
        // durable C1. The retained supervisor handles warm retries by request key.
        if plan.replayed {
            return Err(unreadable(
                "launch retry",
                "the original FULL reservation already exists; reconcile that lifecycle before another native effect",
            ));
        }
        self.check_resume_source(&plan, &work.admission, deadline)
            .await?;
        let mut qualified = self.qualify(&plan, deadline).await?;
        #[cfg(unix)]
        let alias_parent = self
            .alias_parent(harness, &qualified.command.executable, deadline)
            .await?;
        let (pin, bearer) = (token(&format!("sec1.{}.", plan.session))?, token("sels-")?);
        let hashes = LaunchHashes {
            session: Sha256::digest(pin.expose()).into(),
            http: Sha256::digest(bearer.expose()).into(),
        };
        let request = HarnessRequest {
            identity: SessionIdentity {
                project: plan.project.id.clone(),
                agent: plan.agent.id.clone(),
                session: plan.session.clone(),
            },
            executable: NativePath::from_local(qualified.command.executable.clone())?,
            cwd: plan.cwd.clone(),
            profile: plan.profile.clone(),
            policy: qualified.policy.clone(),
            mode: qualified.mode,
            resume: plan.conversation.clone(),
            transcript_roots: plan.control.moved_from_roots.clone(),
            replay: self
                .canonical_replay(&plan, &work.admission, deadline)
                .await?,
            initial_input: Body::new(plan.input.task.clone().unwrap_or_else(|| {
                "Read your StateEngine context and continue your assigned work.".into()
            }))?,
            launch_credential: pin,
            mcp_bearer: bearer,
            key: plan.input.idempotency_key.clone(),
            sign_in: crate::launch_sign_in::current(),
        };
        let (configuration, invocation) = self
            .prepare_invocation(
                &plan,
                harness,
                &mut qualified,
                &request,
                #[cfg(unix)]
                alias_parent,
                deadline,
            )
            .await?;
        let reservation = self
            .commit_reservation(work, &plan, &hashes, deadline)
            .await;
        // Release the per-agent launch serialization guard immediately after C1
        // so provider readiness waits remain interruptible.
        drop(launch_guard.take());
        let reservation = reservation?;
        let scope = self
            .prepare_native_scope(work, &plan, invocation, qualified, reservation, deadline)
            .await?;
        let material = LaunchMaterial {
            request,
            configuration,
            hashes,
        };
        let (request, ticket, transport, argv) = self
            .publish_and_begin_launch(work, &plan, material, scope, deadline)
            .await?;
        self.finish_pending(work, request, transport, ticket, argv, deadline)
            .await
    }

    async fn commit_exec_observed(
        &self,
        work: &mut Work,
        record: &ProcessRecord,
        deadline: &Deadline,
    ) -> Result<()> {
        // Exec custody is an owner-admission fact, not provider readiness.
        // Publish the exact witnessed image before a handshake can stall;
        // C3 still owns Running, credentials and capture activation together.
        let stored = native_record::identity_meta(
            &work.meta,
            CheckpointKind::Process(record.clone()),
            Some((&record.root, record.argv_sha256)),
            Some(record.guarantee),
            self.boot(),
        )?;
        self.change(
            work,
            "exec-observed",
            stored,
            (ProcessState::Starting, ProcessState::Starting),
            deadline,
        )
        .await?;
        let (root, bound) = (record.root.clone(), deadline.at());
        work.process_view = self
            .on_pool(deadline, move || {
                super::launch_util::view_at_launch(&root, bound)
            })
            .await?;
        Ok(())
    }

    async fn finish_pending(
        &self,
        work: &mut Work,
        request: HarnessRequest,
        transport: ProviderTransport,
        mut ticket: LaunchTicket,
        argv: [u8; 32],
        deadline: &Deadline,
    ) -> Result<LaunchResult> {
        #[allow(unused_mut)]
        let mut transport = Some(transport);
        #[allow(unused_mut)]
        let mut prepared = None;
        let record = loop {
            let native = self.native.clone();
            let (returned, progress) = self
                .on_pool(deadline, move || {
                    let result = native
                        .poll_launch(&ticket)
                        .map_err(|e| error("native launch progress", e));
                    Ok((ticket, result))
                })
                .await?;
            ticket = returned;
            match progress? {
                LaunchProgress::Started(success) => {
                    work.exec_observed =
                        matches!(success.exec_observed, se_proc::ProcessObservation::Live(_));
                    work.record = Some(success.record.clone());
                    break success.record;
                }
                LaunchProgress::Failed(failure) => {
                    return Err(error("native launch", failure.error));
                }
                LaunchProgress::AwaitingExecCommit(root) => {
                    let stored = native_record::identity_meta(
                        &work.meta,
                        CheckpointKind::Root((*root).clone()),
                        Some((&root.pre_exec, argv)),
                        Some(root.scope.guarantee),
                        self.boot(),
                    )?;
                    self.change(
                        work,
                        "root-prepared",
                        stored,
                        (ProcessState::Starting, ProcessState::Starting),
                        deadline,
                    )
                    .await?;
                    let native = self.native.clone();
                    ticket = self
                        .on_pool(deadline, move || {
                            native
                                .authorize_exec(&ticket)
                                .map_err(|e| error("exec authorization", e))?;
                            Ok(ticket)
                        })
                        .await?;
                    #[cfg(target_os = "linux")]
                    if request.mode == LaunchMode::Window
                        && work.meta.provider == se_store::Provider::Codex
                    {
                        let backend = transport.take().ok_or_else(|| {
                            error("Codex window", "backend transport was already consumed")
                        })?;
                        prepared = Some(
                            self.join_codex_window(work, &request, backend, deadline)
                                .await?,
                        );
                    }
                }
                LaunchProgress::Pending => wait(&work.wake, deadline).await?,
            }
        };
        self.commit_exec_observed(work, &record, deadline).await?;
        self.attach(
            work,
            request,
            transport.unwrap_or_else(ProviderTransport::console),
            record,
            prepared,
            deadline,
        )
        .await
    }
    pub(super) async fn head(&self, work: &Work, deadline: &Deadline) -> Result<ProjectionRecord> {
        let (target, lifecycle) = (work.meta.agent.id.clone(), work.meta.lifecycle.clone());
        self.store
            .read(work.admission.clone(), deadline, move |cx| {
                se_core::scope::require_present(
                    cx.read
                        .control_target(target.clone())
                        .map_err(store_error)?,
                    "process control target",
                    "Restore the current control grant or use the owner terminal.",
                )?;
                let head = se_core::scope::require_present(
                    cx.read.process(lifecycle.clone()).map_err(store_error)?,
                    "exact process checkpoint",
                    "Keep its original lifecycle for cleanup.",
                )?;
                let identity = match &head.current.body {
                    se_store::EventBody::ProcessRegistered { identity, .. }
                    | se_store::EventBody::ProcessTransition { identity, .. } => identity,
                    _ => return Err(error("process checkpoint", "wrong projection")),
                };
                if identity.record != lifecycle
                    || identity.principal != se_store::Actor::Agent(target)
                {
                    return Err(error("process checkpoint", "target identity differs"));
                }
                Ok(head)
            })
            .await
    }
    pub(super) async fn change(
        &self,
        work: &Work,
        phase: &'static str,
        identity: se_store::ProcessIdentityRecord,
        edge: (ProcessState, ProcessState),
        deadline: &Deadline,
    ) -> Result<se_types::EventId> {
        let previous = self.head(work, deadline).await?;
        let request = work.stop_key.as_ref().unwrap_or(&work.meta.request).clone();
        let receipt = self
            .store
            .commit_fenced(
                work.admission.clone(),
                deadline,
                &work.stop_fence,
                move |kernel, cx| {
                    process_commit::advance(
                        kernel,
                        process_commit::ProcessChange {
                            request,
                            phase,
                            previous,
                            identity,
                            edge,
                        },
                        cx,
                    )
                },
            )
            .await?;
        Ok(receipt.primary_event)
    }
    pub(super) async fn qualify(
        &self,
        plan: &LaunchPlan,
        deadline: &Deadline,
    ) -> Result<Qualified> {
        let (selected, home) = (plan.clone(), self.options.home.clone());
        let configuration = self.options.configuration.clone();
        let (window, policy) = self
            .on_pool(deadline, move || {
                let window = super::window::select(&selected, &configuration)?;
                Ok((window, policy(&selected, &home, &configuration)?))
            })
            .await?;
        let mode = if window.is_some() {
            se_proc::LaunchMode::Window
        } else if plan.profile.provider == se_store::Provider::SeCode {
            se_proc::LaunchMode::HeadlessConsole
        } else if plan.profile.provider == se_store::Provider::Codex {
            se_proc::LaunchMode::HeadlessPersistent
        } else {
            se_proc::LaunchMode::Headless
        };
        let harness = self.harness_for(plan.profile.provider)?;
        let provider = plan.details().provider;
        let (configuration, configuration_file, harness_name) = (
            self.options.configuration.clone(),
            self.configuration_file.clone(),
            plan.profile.harness.clone(),
        );
        let (command, qualification) = self
            .on_pool(deadline, move || {
                let command = resolve_provider_launch(
                    &configuration,
                    provider,
                    configuration_file.as_deref(),
                    harness_name.as_deref(),
                )?;
                // Reuse this existing filesystem job instead of adding queue
                // round trips to the warm qualification path.
                let qualification = if provider == se_types::Provider::Codex {
                    se_proc::native_ipc::ExecutableStamp::observe(&command.executable)
                        .map_err(|e| error("Codex qualification image", e))?
                } else {
                    None
                };
                Ok((command, qualification))
            })
            .await?;
        harness
            .probe_direct(
                ProbeRequest {
                    kind: harness.kind(),
                    command: command.executable.clone(),
                },
                qualification,
                call(self.store.generation, deadline)?,
            )
            .await?;
        Ok(Qualified {
            command,
            window,
            mode,
            policy,
        })
    }

    /// Whether the provider's invoked path must be kept as an alias: a script,
    /// or a link whose resolved image does not qualify on its own.
    #[cfg(unix)]
    pub(super) async fn alias_parent(
        &self,
        harness: &dyn crate::Harness,
        executable: &std::path::Path,
        deadline: &Deadline,
    ) -> Result<bool> {
        let selected = executable.to_path_buf();
        let (image, script) = self
            .on_pool(deadline, move || {
                let image = se_proc::canonicalize_path(&selected)
                    .map_err(|e| error("provider alias image", e))?;
                let script = super::launch_util::script_launcher(&selected)?;
                Ok((image, script))
            })
            .await?;
        if script {
            // A successful version probe does not make a script's image
            // stable: its shebang interpreter can exec another runtime.
            return Ok(true);
        }
        if image == executable {
            return Ok(false);
        }
        // A plain native-provider symlink qualifies through its image
        // too. Multicall dispatch still needs its invoked path.
        let probe = ProbeRequest {
            kind: harness.kind(),
            command: image,
        };
        match harness
            .probe(probe, call(self.store.generation, deadline)?)
            .await
        {
            Ok(_) => Ok(false),
            Err(e)
                if matches!(
                    e.body.detail(),
                    Detail::ProviderIncompatible(_) | Detail::UsageInvalidValue(_)
                ) =>
            {
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }
}
