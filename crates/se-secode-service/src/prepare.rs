//! Private profile bootstrap and authenticated service readiness. Effects stay
//! under the accepted client reservation and their original journal identities.
use super::*;
use se_harness::secode_process::{
    Acceptance, Control, Images, ServiceIdentity, initial_input, vendor_session,
};
use se_proc::{CheckpointKind, ProcessRuntime, StopObservation};
use sha2::{Digest, Sha256};

struct SelectedImageInfo {
    resume_supported: bool,
    server_sha256: se_types::Sha256,
}

impl<H: HostPort> Coordinator<'_, H> {
    pub(crate) async fn secode_server_invocation(
        &self,
        images: &Arc<std::sync::Mutex<Images>>,
        context: &'static str,
        deadline: &Deadline,
    ) -> Result<se_proc::NativeExecutableInvocation> {
        let selected = images.clone();
        self.run_blocking(deadline, move || {
            selected
                .lock()
                .map_err(|_| error(context, "poisoned custody"))?
                .server_invocation()
        })
        .await
    }
    pub async fn prepare_secode(
        &self,
        work: &mut impl SecodeWork,
        request: &se_harness::HarnessRequest,
        images: Arc<std::sync::Mutex<Images>>,
        deadline: &Deadline,
    ) -> Result<Prepared> {
        let slot = self.acquire_secode_slot(request, deadline).await?;
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
        service.persist(self.0, deadline).await?;
        let profile = service.journal.profile.to_local()?;
        let checked_images = images.clone();
        let image_info = self
            .run_blocking(deadline, move || {
                let mut images = checked_images
                    .lock()
                    .map_err(|_| error("SE Code executable custody", "poisoned selected images"))?;
                images.validate()?;
                Ok(SelectedImageInfo {
                    resume_supported: images.resume_supported,
                    server_sha256: images.server_sha256(),
                })
            })
            .await?;
        self.ensure_secode_bootstrap(&mut service, request, &profile, &images, deadline)
            .await?;
        self.configure_secode(&mut service, request, deadline)
            .await?;
        let service_record = self
            .ensure_secode_service_process(
                &mut service,
                request,
                &profile,
                &images,
                &image_info,
                deadline,
            )
            .await?;
        let control = self
            .connect_secode_control(&mut service, &profile, &service_record, deadline)
            .await?;
        let registration = self.secode_readiness(&service, images, deadline).await?;
        self.remember_secode_registration(&mut service, &registration, deadline)
            .await?;
        // The input lookup is authenticated and carries the service's full
        // incarnation even before the original input has been offered.
        work.set_model(Some(
            self.provision_secode(&mut service, request, &registration, deadline)
                .await?,
        ));
        let identity = self
            .confirm_secode_identity(&mut service, &control, &registration, deadline)
            .await?;
        let prepared = Prepared {
            control,
            service: identity,
            live: service.live.clone(),
            profile: service.journal.profile.clone(),
            process: self.0.native_instance(
                &service_record.root,
                service_record.argv_sha256,
                &self.0.epoch().owner.fields().boot,
            )?,
            session: service.journal.vendor_session.clone(),
            initial_input: service.journal.initial_input.clone(),
        };
        *work.secode_mut() = Some(prepared.clone());
        Ok(prepared)
    }
    async fn acquire_secode_slot(
        &self,
        request: &se_harness::HarnessRequest,
        deadline: &Deadline,
    ) -> Result<Arc<tokio::sync::Mutex<Service>>> {
        let key = (
            request.identity.project.clone(),
            request.identity.agent.clone(),
        );
        let mut services = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.at()),
            self.0.services().0.lock(),
        )
        .await
        .map_err(|_| {
            error(
                "SE Code service custody",
                "another retained preparation is busy",
            )
        })?;
        if let Some(slot) = services.get(&key) {
            return Ok(slot.clone());
        }
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
            >= self.0.maximum_sessions() as usize
        {
            return Err(error(
                "SE Code service budget",
                "stop a retained private service before creating another",
            ));
        }
        let path = Journal::path(self.0.home(), &key.0, &key.1);
        let profile = Journal::profile(self.0.home(), &key.0, &key.1);
        let read_path = path.clone();
        let custody_deadline = deadline.clone();
        if self
            .run_blocking(deadline, move || {
                Journal::read::<H>(&read_path, &custody_deadline)
            })
            .await?
            .is_some()
        {
            return Err(error(
                "SE Code service recovery",
                "the original private journal must be reconciled at runtime startup before another service can be created",
            ));
        }
        let slot = Arc::new(tokio::sync::Mutex::new(new_secode_service(
            request, path, profile,
        )?));
        services.insert(key, slot.clone());
        Ok(slot)
    }
    async fn ensure_secode_bootstrap(
        &self,
        service: &mut Service,
        request: &se_harness::HarnessRequest,
        profile: &std::path::Path,
        images: &Arc<std::sync::Mutex<Images>>,
        deadline: &Deadline,
    ) -> Result<()> {
        if service.journal.bootstrap.is_none() {
            let server = self
                .secode_server_invocation(images, "SE Code bootstrap image", deadline)
                .await?;
            let mut arguments = vec![
                "init-profile".into(),
                "--service".into(),
                profile.as_os_str().to_owned(),
            ];
            if let Some(seed) = &self.0.configuration().providers.secode.seed_profile {
                arguments.extend(["--from".into(), seed.into()]);
            }
            self.start_secode_auxiliary(
                service,
                AuxiliaryLaunch {
                    auxiliary: Auxiliary::Bootstrap,
                    executable: server,
                    arguments,
                    cwd: request.cwd.to_local()?,
                    policy: request.policy.clone(),
                    input: None,
                },
                deadline,
            )
            .await?;
        }
        if !matches!(
            service.journal.bootstrap.as_ref().map(|v| &v.checkpoint),
            Some(CheckpointKind::Exit { .. })
        ) {
            self.wait_secode_bootstrap_exit(service, deadline).await?;
        }
        if !matches!(
            service.journal.bootstrap.as_ref().map(|c| &c.checkpoint),
            Some(CheckpointKind::Exit { witness, .. }) if root_exited_zero(&witness.root)
        ) {
            return Err(error(
                "SE Code profile bootstrap",
                "the original initializer has no successful native exit; preserve its bounded diagnostics and private profile",
            ));
        }
        Ok(())
    }
    async fn wait_secode_bootstrap_exit(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        loop {
            let owner = service
                .bootstrap
                .clone()
                .ok_or_else(|| error("SE Code bootstrap", "native initializer reference absent"))?;
            let observed = self
                .run_native(deadline, move |native| {
                    native
                        .witness_exit(&owner)
                        .map_err(|e| error("SE Code bootstrap exit", e))
                })
                .await?;
            if let StopObservation::Complete(witness) = observed {
                let success = root_exited_zero(&witness.root);
                self.retire_secode_auxiliary(service, Auxiliary::Bootstrap, &witness, deadline)
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
                return Ok(());
            }
            // A native exit nudge can precede the final scope/wait-status
            // observation. Recheck within the original deadline even when
            // there is no second notification for the completed child.
            native::sleep_poll_interval(deadline).await?;
        }
    }
    async fn ensure_secode_service_process(
        &self,
        service: &mut Service,
        request: &se_harness::HarnessRequest,
        profile: &std::path::Path,
        images: &Arc<std::sync::Mutex<Images>>,
        image_info: &SelectedImageInfo,
        deadline: &Deadline,
    ) -> Result<se_proc::ProcessRecord> {
        if service.journal.service.is_none() {
            service.register_image(image_info.server_sha256, image_info.resume_supported);
            service.persist(self.0, deadline).await?;
            let arguments = vec![
                "serve-service".into(),
                "--service".into(),
                profile.as_os_str().to_owned(),
                "--port".into(),
                "0".into(),
                "--external-host".into(),
            ];
            let server = self
                .secode_server_invocation(images, "SE Code service image", deadline)
                .await?;
            self.start_secode_auxiliary(
                service,
                AuxiliaryLaunch {
                    auxiliary: Auxiliary::Service,
                    executable: server,
                    arguments,
                    cwd: request.cwd.to_local()?,
                    policy: request.policy.clone(),
                    input: None,
                },
                deadline,
            )
            .await?;
        }
        match service.journal.service.as_ref().map(|v| &v.checkpoint) {
            Some(CheckpointKind::Process(record)) => Ok(record.clone()),
            _ => Err(error(
                "SE Code private service",
                "original process is not ready; reconcile its native checkpoint",
            )),
        }
    }
    async fn connect_secode_control(
        &self,
        service: &mut Service,
        profile: &std::path::Path,
        service_record: &se_proc::ProcessRecord,
        deadline: &Deadline,
    ) -> Result<Arc<Control>> {
        if let Some(control) = &service.control {
            return Ok(control.clone());
        }
        let control = loop {
            let path = profile.to_path_buf();
            let ready = self.run_blocking(deadline, move || ready(&path)).await?;
            let owner = service
                .process
                .clone()
                .ok_or_else(|| error("SE Code service readiness", "owned process absent"))?;
            let observed = self
                .run_native(deadline, move |native| {
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
                let path = profile.to_path_buf();
                let origin = endpoint.clone();
                let control = Arc::new(
                    self.run_blocking(deadline, move || Control::open(&path, &origin))
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
                service.persist(self.0, deadline).await?;
                break control;
            }
            native::sleep_poll_interval(deadline).await?;
        };
        service.control = Some(control.clone());
        Ok(control)
    }
    async fn confirm_secode_identity(
        &self,
        service: &mut Service,
        control: &Control,
        registration: &readiness::Registration,
        deadline: &Deadline,
    ) -> Result<ServiceIdentity> {
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
        let receipt: Acceptance = serde_json::from_value(receipt)
            .map_err(|e| error("SE Code original input readback", e))?;
        let identity = receipt.service;
        identity.validate()?;
        registration.require_same(&identity)?;
        record_secode_identity(service, identity.clone())?;
        service.persist(self.0, deadline).await?;
        Ok(identity)
    }
}
pub(crate) fn record_secode_identity(
    service: &mut Service,
    identity: ServiceIdentity,
) -> Result<()> {
    if let Some(original) = &service.journal.identity {
        original.require_same(&identity)?;
    }
    service.journal.identity = Some(identity);
    Ok(())
}
fn root_exited_zero(root: &se_proc::RootWitness) -> bool {
    matches!(
        root,
        se_proc::RootWitness::Identified {
            status: se_proc::ExitStatus::Code(0),
            ..
        }
    )
}
fn new_secode_service(
    request: &se_harness::HarnessRequest,
    path: PathBuf,
    profile: PathBuf,
) -> Result<Service> {
    let session = vendor_session(request)?;
    let initial = initial_input(request);
    let journal = Journal {
        version: 1,
        retired: false,
        lost: CustodyState::Intact,
        stop_failure: None,
        project: request.identity.project.clone(),
        agent: request.identity.agent.clone(),
        profile: NativePath::from_local(profile)?,
        session: request.identity.session.clone(),
        vendor_session: session,
        initial_input: initial,
        initial_sha256: se_types::Sha256::from_bytes(
            Sha256::digest(request.initial_input.as_str().as_bytes()).into(),
        ),
        initial_offered: InitialOffer::Pending,
        session_create_attempted: SessionCreation::NotAttempted,
        policy_sha256: None,
        previous_policy_sha256: None,
        client_closed: None,
        resume_release: None,
        input_free_resume: ResumeSupport::Unavailable,
        notice: None,
        restart_key: None,
        restart_effect: None,
        restart_settled: false,
        restart_reply_sent: RestartReply::Pending,
        superseded_by_restart: RestartSupersession::Current,
        bootstrap: None,
        service: None,
        retirement: None,
        registration: None,
        server_sha256: None,
        endpoint: None,
        identity: None,
        capability_repair: None,
    };
    Ok(Service {
        restart: None,
        journal,
        path,
        digest: None,
        pending_save: None,
        wake: Arc::new(Wake::default()),
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
    })
}
pub fn ready(profile: &std::path::Path) -> Result<Option<serde_json::Value>> {
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
