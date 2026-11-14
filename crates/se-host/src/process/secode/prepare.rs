//! Private profile bootstrap and authenticated service readiness. Effects stay
//! under the accepted client reservation and their original journal identities.
use super::*;
use crate::harness::secode_process::{Control, Images, initial_input, vendor_session};
use se_proc::{CheckpointKind, ProcessRuntime, StopObservation};
use sha2::{Digest, Sha256};

impl LaunchCoordinator {
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(in crate::process) async fn prepare_secode(
        &self,
        work: &mut owned::Work,
        request: &crate::HarnessRequest,
        images: Arc<std::sync::Mutex<Images>>,
        deadline: &Deadline,
    ) -> Result<Prepared> {
        let key = (
            request.identity.project.clone(),
            request.identity.agent.clone(),
        );
        let mut services = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.at()),
            self.secode_services.0.lock(),
        )
        .await
        .map_err(|_| {
            error(
                "SE Code service custody",
                "another retained preparation is busy",
            )
        })?;
        if !services.contains_key(&key) {
            if services
                .values()
                .filter(|slot| {
                    slot.try_lock().map_or(true, |service| {
                        service.process.is_some()
                            || service.bootstrap.is_some()
                            || service.retirement.is_some()
                            || service.failure.is_some()
                    })
                })
                .count()
                >= self.options.maximum_sessions as usize
            {
                return Err(error(
                    "SE Code service budget",
                    "stop a retained private service before creating another",
                ));
            }
            let path = Journal::path(&self.options.home, &key.0, &key.1);
            let profile = Journal::profile(&self.options.home, &key.0, &key.1);
            let retained = self
                .store
                .pool
                .run_owned(deadline, {
                    let path = path.clone();
                    let custody_deadline = deadline.clone();
                    move || Journal::read(&path, &custody_deadline)
                })
                .await?;
            if retained.is_some() {
                return Err(error(
                    "SE Code service recovery",
                    "the original private journal must be reconciled at runtime startup before another service can be created",
                ));
            }
            let session = vendor_session(request)?;
            let initial = initial_input(request);
            let journal = Journal {
                version: 1,
                retired: false,
                lost: false,
                stop_failure: None,
                project: key.0.clone(),
                agent: key.1.clone(),
                profile: NativePath::from_local(profile)?,
                session: request.identity.session.clone(),
                vendor_session: session,
                initial_input: initial,
                initial_sha256: se_types::Sha256::from_bytes(
                    Sha256::digest(request.initial_input.as_str().as_bytes()).into(),
                ),
                initial_offered: false,
                session_create_attempted: false,
                policy_sha256: None,
                previous_policy_sha256: None,
                client_closed: None,
                resume_release: None,
                input_free_resume: false,
                notice: None,
                bootstrap: None,
                service: None,
                retirement: None,
                registration: None,
                server_sha256: None,
                endpoint: None,
                identity: None,
                capability_repair: None,
            };
            services.insert(
                key.clone(),
                Arc::new(tokio::sync::Mutex::new(Service {
                    journal,
                    path,
                    digest: None,
                    pending_save: None,
                    wake: Arc::new(events::Wake::default()),
                    bootstrap: None,
                    process: None,
                    retirement: None,
                    bootstrap_output: None,
                    service_output: None,
                    retirement_output: None,
                    control: None,
                    failure: None,
                    capability_failure: None,
                    live: Default::default(),
                    capability_check_at: None,
                })),
            );
        }
        let slot = services
            .get(&key)
            .cloned()
            .ok_or_else(|| error("SE Code service custody", "retained service disappeared"))?;
        drop(services);
        let mut service = lock_service(&slot, deadline).await?;
        if let Some(failure) = &service.failure
            && !service.journal.retired
        {
            return Err(error("SE Code retained service", failure));
        }
        if service.journal.session != request.identity.session {
            self.replace_secode_session(&mut service, work, request, deadline)
                .await?;
        }
        service.persist(self, deadline).await?;
        let profile = service.journal.profile.to_local()?;
        let checked_images = images.clone();
        let (resume_supported, server_sha256) = self
            .store
            .pool
            .run_owned(deadline, move || {
                let mut images = checked_images
                    .lock()
                    .map_err(|_| error("SE Code executable custody", "poisoned selected images"))?;
                images.validate()?;
                Ok((images.resume_supported, images.server_sha256()))
            })
            .await?;
        if service.journal.bootstrap.is_none() {
            let selected = images.clone();
            let server = self
                .store
                .pool
                .run_owned(deadline, move || {
                    selected
                        .lock()
                        .map_err(|_| error("SE Code bootstrap image", "poisoned custody"))?
                        .server_invocation()
                })
                .await?;
            let mut arguments = vec![
                "init-profile".into(),
                "--service".into(),
                profile.as_os_str().to_owned(),
            ];
            if let Some(seed) = &self.options.configuration.providers.secode.seed_profile {
                arguments.extend(["--from".into(), seed.into()]);
            }
            self.start_secode_auxiliary(
                &mut service,
                Auxiliary::Bootstrap,
                server,
                arguments,
                request.cwd.to_local()?,
                request.policy.clone(),
                None,
                deadline,
            )
            .await?;
        }
        if !matches!(
            service.journal.bootstrap.as_ref().map(|v| &v.checkpoint),
            Some(CheckpointKind::Exit { .. })
        ) {
            loop {
                let native = self.native.clone();
                let owner = service.bootstrap.clone().ok_or_else(|| {
                    error("SE Code bootstrap", "native initializer reference absent")
                })?;
                let observed = self
                    .store
                    .pool
                    .run_owned(deadline, move || {
                        native
                            .witness_exit(&owner)
                            .map_err(|e| error("SE Code bootstrap exit", e))
                    })
                    .await?;
                if let StopObservation::Complete(witness) = observed {
                    let success = matches!(
                        witness.root,
                        se_proc::RootWitness::Identified {
                            status: se_proc::ExitStatus::Code(0),
                            ..
                        }
                    );
                    self.retire_secode_auxiliary(
                        &mut service,
                        Auxiliary::Bootstrap,
                        &witness,
                        deadline,
                    )
                    .await?;
                    if !success {
                        return Err(error(
                            "SE Code profile bootstrap",
                            format!(
                                "initializer did not exit successfully; bounded private diagnostic: {}; no retry was made",
                                service
                                    .bootstrap_output
                                    .as_ref()
                                    .map(|output| output.path().display().to_string())
                                    .unwrap_or_else(|| "unavailable after runtime recovery".into())
                            ),
                        ));
                    }
                    break;
                }
                // A native exit nudge can precede the final scope/wait-status
                // observation. Recheck within the original deadline even when
                // there is no second notification for the completed child.
                tokio::time::sleep(
                    deadline
                        .remaining()?
                        .min(std::time::Duration::from_millis(25)),
                )
                .await;
            }
        }
        if !matches!(service.journal.bootstrap.as_ref().map(|c|&c.checkpoint), Some(CheckpointKind::Exit {witness,..}) if matches!(witness.root,se_proc::RootWitness::Identified {status:se_proc::ExitStatus::Code(0),..}))
        {
            return Err(error(
                "SE Code profile bootstrap",
                "the original initializer has no successful native exit; preserve its bounded diagnostics and private profile",
            ));
        }
        self.configure_secode(&mut service, request, deadline)
            .await?;
        if service.journal.service.is_none() {
            service.journal.input_free_resume = resume_supported;
            service.journal.server_sha256 = Some(server_sha256);
            service.journal.retired = false;
            service.persist(self, deadline).await?;
            let arguments = vec![
                "serve-service".into(),
                "--service".into(),
                profile.as_os_str().to_owned(),
                "--port".into(),
                "0".into(),
                "--external-host".into(),
            ];
            let selected = images.clone();
            let server = self
                .store
                .pool
                .run_owned(deadline, move || {
                    selected
                        .lock()
                        .map_err(|_| error("SE Code service image", "poisoned custody"))?
                        .server_invocation()
                })
                .await?;
            self.start_secode_auxiliary(
                &mut service,
                Auxiliary::Service,
                server,
                arguments,
                request.cwd.to_local()?,
                request.policy.clone(),
                None,
                deadline,
            )
            .await?;
        }
        let service_record = match service.journal.service.as_ref().map(|v| &v.checkpoint) {
            Some(CheckpointKind::Process(record)) => record.clone(),
            _ => {
                return Err(error(
                    "SE Code private service",
                    "original process is not ready; reconcile its native checkpoint",
                ));
            }
        };
        let control = if let Some(control) = &service.control {
            control.clone()
        } else {
            let control = loop {
                let path = profile.clone();
                let ready = self
                    .store
                    .pool
                    .run_owned(deadline, move || ready(&path))
                    .await?;
                let native = self.native.clone();
                let owner = service
                    .process
                    .clone()
                    .ok_or_else(|| error("SE Code service readiness", "owned process absent"))?;
                let observed = self
                    .store
                    .pool
                    .run_owned(deadline, move || {
                        native
                            .observe(&owner)
                            .map_err(|e| error("SE Code service readiness", e))
                    })
                    .await?;
                if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
                    return Err(error(
                        "SE Code service readiness",
                        "the original service exited before authenticated readiness",
                    ));
                }
                if let Some(ready) = ready {
                    if ready["pid"].as_u64() != Some(u64::from(service_record.root.pid.0)) {
                        return Err(error(
                            "SE Code ready receipt",
                            "receipt PID differs from retained service birth",
                        ));
                    }
                    let endpoint = ready["observed_endpoint"]
                        .as_str()
                        .ok_or_else(|| error("SE Code ready receipt", "endpoint absent"))?
                        .to_owned();
                    let path = profile.clone();
                    let origin = endpoint.clone();
                    let control = Arc::new(
                        self.store
                            .pool
                            .run_owned(deadline, move || Control::open(&path, &origin))
                            .await?,
                    );
                    let health = control.read(&["api", "health"], deadline).await?;
                    if health.is_null() {
                        return Err(error(
                            "SE Code authenticated health",
                            "empty health response",
                        ));
                    }
                    service.journal.endpoint = Some(endpoint);
                    service.persist(self, deadline).await?;
                    break control;
                }
                let remaining = deadline.remaining()?;
                tokio::time::sleep(remaining.min(std::time::Duration::from_millis(25))).await;
            };
            service.control = Some(control.clone());
            control
        };
        let registration = self.secode_readiness(&service, images, deadline).await?;
        self.remember_secode_registration(&mut service, &registration, deadline)
            .await?;
        // The input lookup is authenticated and carries the service's full
        // incarnation even before the original input has been offered.
        work.meta.model = Some(
            self.provision_secode(&mut service, request, &registration, deadline)
                .await?,
        );
        let receipt = control
            .read(
                &[
                    "api",
                    "session",
                    &service.journal.vendor_session,
                    "input",
                    &service.journal.initial_input,
                ],
                deadline,
            )
            .await?;
        let receipt: crate::harness::secode_process::Acceptance =
            serde_json::from_value(receipt)
                .map_err(|e| error("SE Code original input readback", e))?;
        let identity = receipt.service;
        identity.validate()?;
        registration.require_same(&identity)?;
        if let Some(original) = &service.journal.identity {
            original.require_same(&identity)?;
        }
        service.journal.identity = Some(identity.clone());
        service.persist(self, deadline).await?;
        let prepared = Prepared {
            control,
            service: identity,
            live: service.live.clone(),
            profile: service.journal.profile.clone(),
            process: native_record::instance(
                &service_record.root,
                service_record.argv_sha256,
                &self.options.epoch.owner.fields().boot,
            )?,
            session: service.journal.vendor_session.clone(),
            initial_input: service.journal.initial_input.clone(),
        };
        work.secode = Some(prepared.clone());
        Ok(prepared)
    }
}
pub(super) fn ready(profile: &std::path::Path) -> Result<Option<serde_json::Value>> {
    let _files = se_proc::NativeProfileFiles::open(profile)
        .map_err(|e| error("SE Code profile custody", e))?;
    // The vendor's public receipt is not a secret file. Its owner-only parent
    // and native read pin protect its identity without requiring private mode.
    let path = profile.join("serve-ready.json");
    let Some(mut file) =
        se_proc::NativeSourcePin::open(&path).map_err(|e| error("SE Code ready read", e))?
    else {
        return Ok(None);
    };
    let bytes = file
        .read_at(0, 65537)
        .map_err(|e| error("SE Code ready read", e))?;
    if bytes.bytes.len() > 65536 || !bytes.end_of_file {
        return Err(error("SE Code ready read", "receipt exceeds 64 KiB"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes.bytes).map_err(|e| error("SE Code ready read", e))?;
    file.validate_path(&path)
        .map_err(|e| error("SE Code ready readback", e))?;
    if value["schema"] != "secode.product.ready.v2" || value["operation"] != "serve" {
        return Err(error(
            "SE Code ready receipt",
            "unsupported schema or operation",
        ));
    }
    Ok(Some(value))
}
