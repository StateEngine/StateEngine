//! Ordered launch barriers and real provider readiness. The supervisor retains
//! every intermediate native reference and file digest through failures.
use super::launch_util::{call, policy, resolve_provider_command, token, wait};
use super::*;
use crate::{HarnessRequest, ProbeRequest, SessionIdentity, client::lease::Deadline};
use se_core::ops::{LaunchResult, process_commit};
use se_proc::{CheckpointKind, LaunchProgress, LaunchStart, ProcessRuntime};
use se_store::{ProcessState, ProjectionRecord, Snapshot};
use se_types::{Body, Result};
use sha2::{Digest, Sha256};

pub(super) use super::owned::Work;
impl LaunchCoordinator {
    pub(super) async fn start(&self, work: &mut Work, deadline: &Deadline) -> Result<LaunchResult> {
        let plan = work.plan.clone().ok_or_else(|| {
            se_core::scope::unreadable(
                "launch execution",
                "a recovered lifecycle cannot create another provider",
            )
        })?;
        let configuration = self.options.configuration.clone();
        let selected = plan.clone();
        let window = self
            .store
            .pool
            .run_owned(deadline, move || {
                super::window::select(&selected, &configuration)
            })
            .await?;
        let mode = if window.is_some() {
            se_proc::LaunchMode::Window
        } else {
            se_proc::LaunchMode::Headless
        };
        let harness = self.harness_for(plan.profile.provider)?;
        if !plan.control.processes.is_empty()
            || plan
                .control
                .sessions
                .iter()
                .any(|s| !matches!(s.current.body, se_store::EventBody::SessionPrepared { .. }))
        {
            return Err(se_types::SeError::invalid(
                "launch target state",
                "stop or reconcile the target's existing live preparation before a new launch",
            ));
        }
        // A cold retry is never allowed to allocate another native child over a
        // durable C1. The retained supervisor handles warm retries by request key.
        if plan.replayed {
            return Err(se_core::scope::unreadable(
                "launch retry",
                "the original FULL reservation already exists; reconcile that lifecycle before another native effect",
            ));
        }
        let provider = match plan.profile.provider {
            se_store::Provider::Codex => se_types::Provider::Codex,
            _ => se_types::Provider::Claude,
        };
        let command = self
            .options
            .configuration
            .provider_command(provider)
            .to_owned();
        let home = self.options.home.clone();
        let executable = self
            .store
            .pool
            .run_owned(deadline, move || {
                resolve_provider_command(&command, provider, &home)
            })
            .await?;
        harness
            .probe(
                ProbeRequest {
                    kind: harness.kind(),
                    command: executable.clone(),
                },
                call(self.store.generation, deadline)?,
            )
            .await?;
        let identity = SessionIdentity {
            project: plan.project.id.clone(),
            agent: plan.agent.id.clone(),
            session: plan.session.clone(),
        };
        let pin = token(&format!("sec1.{}.", plan.session))?;
        let bearer = token("sels-")?;
        let session_hash = Sha256::digest(pin.expose()).into();
        let http_hash = Sha256::digest(bearer.expose()).into();
        let policy = policy(&plan, &self.options.home)?;
        let request = HarnessRequest {
            identity,
            executable: NativePath::from_local(executable)?,
            cwd: plan.cwd.clone(),
            profile: plan.profile.clone(),
            policy: policy.clone(),
            mode,
            resume: plan.conversation.clone(),
            initial_input: Body::new(plan.input.task.clone().unwrap_or_else(|| {
                "Read your StateEngine context and continue your assigned work.".into()
            }))?,
            launch_credential: pin,
            mcp_bearer: bearer,
            key: plan.input.idempotency_key.clone(),
        };
        let configuration = harness
            .configuration(&request, call(self.store.generation, deadline)?)
            .await?;
        let mut invocation = harness
            .invocation(&request, call(self.store.generation, deadline)?)
            .await?;
        if mode == se_proc::LaunchMode::Window && cfg!(target_os = "linux") {
            invocation
                .environment
                .entries
                .retain(|(key, _)| key != "TERM");
            invocation
                .environment
                .entries
                .push(("TERM".into(), "xterm-256color".into()));
        }
        let provider_pipes = mode == se_proc::LaunchMode::Headless
            || plan.profile.provider == se_store::Provider::Codex;
        let mut nonce = [0; 16];
        se_proc::fill_entropy(&mut nonce).map_err(|e| error("launch scope entropy", e))?;
        let reservation = se_proc::LaunchReservation {
            format_version: 1,
            lifecycle: plan.lifecycle.clone(),
            host: self.host,
            owner: self.owner.clone(),
            generation: self.options.epoch.generation,
            scope_nonce: nonce,
            parent: if cfg!(windows) {
                se_proc::ReservationParent::Windows
            } else {
                se_proc::ReservationParent::LinuxTracked
            },
            created_at_unix_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| error("launch clock", e))?
                .as_nanos(),
        };
        work.reservation = Some(reservation.clone());
        let stored = native_record::identity(
            &plan,
            CheckpointKind::Reservation(reservation.clone()),
            None,
            None,
            &self.options.epoch.owner.fields().boot,
        )?;
        let saved = plan.clone();
        let reserved = self
            .store
            .commit(
                work.admission.clone(),
                deadline,
                Some(plan.seed.clone()),
                move |kernel, cx| {
                    process_commit::reserve(kernel, &saved, stored, session_hash, http_hash, cx)
                },
            )
            .await;
        if let Err(failure) = reserved {
            work.reservation_uncertain = matches!(
                failure.body.detail(),
                se_types::Detail::CommitOutcomeUnknown(_)
                    | se_types::Detail::CommittedResponseUnavailable(_)
            );
            return Err(failure);
        }

        work.committed = true;
        self.proofs.register(
            plan.session.clone(),
            self.store.generation.get(),
            session_hash,
            http_hash,
        )?;
        work.pin_hash = Some(session_hash);
        work.files = configuration
            .ephemeral_files
            .iter()
            .map(|item| {
                Ok((
                    item.path.to_local()?,
                    Sha256::digest(item.contents.expose()).into(),
                ))
            })
            .collect::<Result<_>>()?;
        let manifest = files::manifest(&self.options.home, &plan, session_hash, &configuration)?;
        work.files
            .push((manifest.0.clone(), Sha256::digest(&manifest.1).into()));
        let home = self.options.home.clone();
        let session = plan.session.clone();
        let request = self
            .store
            .pool
            .run_owned(deadline, move || {
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
        if plan.profile.provider == se_store::Provider::Codex {
            self.codex
                .prepare_socket(&request, &call(self.store.generation, deadline)?)
                .await?;
        }
        let spec = se_proc::LaunchSpec {
            lifecycle: plan.lifecycle.clone(),
            generation: self.options.epoch.generation,
            executable: invocation.executable.to_local()?,
            arguments: invocation.arguments,
            cwd: plan.cwd.to_local()?,
            environment: invocation.environment,
            stdio: se_proc::StandardIo {
                stdin: None,
                stdout: None,
                stderr: None,
            },
            mode,
            window,
            policy,
            deadline: deadline.at(),
            notifications: work.wake.clone(),
        };
        let native = self.native.clone();
        let prepared = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .prepare_launch(reservation, spec)
                    .map_err(|e| error("native scope preparation", e))
            })
            .await?;
        let owner = Arc::new(prepared.process);
        work.process = Some(owner.clone());
        let stored = native_record::identity(
            &plan,
            CheckpointKind::Scope(prepared.checkpoint.clone()),
            None,
            Some(prepared.checkpoint.guarantee),
            &self.options.epoch.owner.fields().boot,
        )?;
        self.change(
            work,
            "scope-prepared",
            stored,
            (ProcessState::Reserved, ProcessState::Starting),
            deadline,
        )
        .await?;
        let io = self.io.clone();
        let identity = request.identity.clone();
        let runtime = self.store.pool.handle();
        let io = if !provider_pipes {
            crate::ProviderIo {
                child: se_proc::StandardIo {
                    stdin: None,
                    stdout: None,
                    stderr: None,
                },
                host: crate::ProviderTransport::console(),
            }
        } else {
            self.store
                .pool
                .run_owned(deadline, move || {
                    let _entered = runtime.enter();
                    io.open(&owner, &identity)
                })
                .await?
        };
        let native = self.native.clone();
        let ticket = self
            .store
            .pool
            .run_owned(deadline, move || {
                if provider_pipes {
                    native
                        .bind_stdio(&prepared.prepared, io.child)
                        .map_err(|e| error("provider stream binding", e))?;
                }
                match native.begin_launch(prepared.prepared) {
                    LaunchStart::Pending { ticket, .. } => {
                        Ok((ticket, io.host, prepared.argv_sha256))
                    }
                    LaunchStart::Failed(failure) => Err(error("native launch", failure.error)),
                }
            })
            .await?;
        let (ticket, transport, argv) = ticket;
        self.finish_pending(work, request, transport, ticket, argv, deadline)
            .await
    }
    async fn finish_pending(
        &self,
        work: &mut Work,
        request: HarnessRequest,
        transport: crate::ProviderTransport,
        mut ticket: se_proc::LaunchTicket,
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
                .store
                .pool
                .run_owned(deadline, move || {
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
                        &self.options.epoch.owner.fields().boot,
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
                        .store
                        .pool
                        .run_owned(deadline, move || {
                            native
                                .authorize_exec(&ticket)
                                .map_err(|e| error("exec authorization", e))?;
                            Ok(ticket)
                        })
                        .await?;
                    #[cfg(target_os = "linux")]
                    if request.mode == se_proc::LaunchMode::Window
                        && work.meta.provider == se_store::Provider::Codex
                    {
                        prepared = Some(
                            self.join_codex_window(
                                work,
                                &request,
                                transport.take().ok_or_else(|| {
                                    error("Codex window", "backend transport was already consumed")
                                })?,
                                deadline,
                            )
                            .await?,
                        );
                    }
                }
                LaunchProgress::Pending => wait(&work.wake, deadline).await?,
            }
        };
        let root = record.root.clone();
        let bound = deadline.at();
        work.process_view = Some(
            self.store
                .pool
                .run_owned(deadline, move || super::launch_util::view(&root, bound))
                .await?,
        );
        self.attach(
            work,
            request,
            transport.unwrap_or_else(crate::ProviderTransport::console),
            record,
            prepared,
            deadline,
        )
        .await
    }
    pub(super) async fn head(&self, work: &Work, deadline: &Deadline) -> Result<ProjectionRecord> {
        let target = work.meta.agent.id.clone();
        let lifecycle = work.meta.lifecycle.clone();
        self.store
            .read(work.admission.clone(), deadline, move |cx| {
                se_core::scope::require_present(
                    cx.read
                        .control_target(target.clone())
                        .map_err(|e| se_core::store_error::store_error(&e))?,
                    "process control target",
                    "Restore the current control grant or use the owner terminal.",
                )?;
                let head = se_core::scope::require_present(
                    cx.read
                        .process(lifecycle.clone())
                        .map_err(|e| se_core::store_error::store_error(&e))?,
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
            .commit(work.admission.clone(), deadline, None, move |kernel, cx| {
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
            })
            .await?;
        Ok(receipt.primary_event)
    }
}
