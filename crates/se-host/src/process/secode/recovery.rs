//! Recover the private service before recovering its clients. Retained endpoint
//! text grants no authority until native birth and authenticated incarnation join.
use super::*;
use crate::harness::secode_process::Control;
use se_proc::{CheckpointKind, CheckpointSource, ProcessRuntime, RecoveryOutcome};

impl LaunchCoordinator {
    pub(in crate::process) async fn recover_secode_services(
        &self,
        deadline: &Deadline,
    ) -> Result<Vec<String>> {
        let home = self.options.home.clone();
        let inventory = match self
            .store
            .pool
            .run_owned(deadline, move || inventory(&home))
            .await
        {
            Ok(inventory) => inventory,
            Err(failure) => {
                let reason = failure.to_string();
                *self.secode_services.1.lock().map_err(|_| {
                    error("SE Code custody inventory", "poisoned inventory state")
                })? = Some(reason.clone());
                return Ok(vec![reason]);
            }
        };
        let mut retained = Vec::new();
        let mut services = self.secode_services.0.lock().await;
        for (path, journal, digest) in inventory {
            let key = (journal.project.clone(), journal.agent.clone());
            if services.contains_key(&key) {
                continue;
            }
            services.insert(
                key.clone(),
                Arc::new(tokio::sync::Mutex::new(Service {
                    journal,
                    path,
                    digest: Some(digest),
                    wake: Arc::new(events::Wake::default()),
                    bootstrap: None,
                    process: None,
                    retirement: None,
                    bootstrap_output: None,
                    service_output: None,
                    retirement_output: None,
                    control: None,
                    failure: None,
                })),
            );
            let slot = services
                .get(&key)
                .cloned()
                .ok_or_else(|| error("SE Code service recovery", "retained entry disappeared"))?;
            retained.push((key, slot));
        }
        drop(services);
        // A nonresponsive service spends its own recovery window; other
        // agents retain time for native client reconciliation at startup.
        let mut recovering = retained.iter().map(|(key, slot)| async {
            let mut service = lock_service(slot, deadline).await?;
            let result = match deadline.stage(std::time::Duration::from_secs(5)) {
                Ok(bound) => self.recover_secode_service(&mut service, &bound).await,
                Err(error) => Err(error),
            };
            Ok::<_, se_types::SeError>(if let Err(error) = result {
                let failure = format!(
                    "private SE Code service for agent {}: {error}; no replacement service or input was created",
                    key.1
                );
                service.failure = Some(failure.clone());
                Some(failure)
            } else { None })
        }).collect::<futures_util::stream::FuturesUnordered<_>>();
        use futures_util::StreamExt;
        let mut failures = Vec::new();
        while let Some(result) = recovering.next().await {
            match result {
                Ok(Some(failure)) => failures.push(failure),
                Ok(None) => (),
                Err(error) => failures.push(error.to_string()),
            }
        }
        Ok(failures)
    }
    async fn recover_secode_service(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        for auxiliary in Auxiliary::ALL {
            let checkpoint = service.journal.auxiliary(auxiliary).clone();
            let Some(checkpoint) = checkpoint else {
                continue;
            };
            let native = self.native.clone();
            let source = match &checkpoint.checkpoint {
                CheckpointKind::Exit { source, .. } => recovery_source(source),
                _ => custody::source(&checkpoint)?,
            };
            let generation = self.options.epoch.generation;
            let outcome = self
                .store
                .pool
                .run_owned(deadline, move || {
                    let plan = native
                        .plan_recovery(source)
                        .map_err(|e| error("SE Code native recovery plan", e))?;
                    native
                        .recover(plan, generation)
                        .map_err(|e| error("SE Code native recovery", e))
                })
                .await?;
            match outcome {
                RecoveryOutcome::Recovered { process, record } => {
                    *service.owner_mut(auxiliary) = Some(Arc::new(process));
                    if matches!(checkpoint.checkpoint, CheckpointKind::Exit { .. }) {
                        return Err(error(
                            "SE Code service recovery",
                            "a terminal checkpoint has a live native scope; retain custody for explicit reconciliation",
                        ));
                    }
                    service.checkpoint(auxiliary, CheckpointKind::Process(*record));
                    service.persist(self, deadline).await?;
                }
                RecoveryOutcome::PendingScope {
                    process,
                    checkpoint,
                } => {
                    *service.owner_mut(auxiliary) = Some(Arc::new(process));
                    service.checkpoint(auxiliary, CheckpointKind::Scope(*checkpoint));
                    service.persist(self, deadline).await?;
                    return Err(error(
                        "SE Code pre-exec recovery",
                        "original scope is retained; finish its cleanup before another launch",
                    ));
                }
                RecoveryOutcome::Exited(witness) => {
                    // Recovery proves present absence, but cannot recover an
                    // old parent's wait status. Keep the already witnessed
                    // initializer result rather than replacing it with
                    // NotOurChild and making every later launch refuse.
                    if matches!(checkpoint.checkpoint, CheckpointKind::Exit { .. }) {
                        continue;
                    }
                    let source = match checkpoint.checkpoint {
                        CheckpointKind::Reservation(v) => {
                            Box::new(CheckpointSource::Reservation(v))
                        }
                        CheckpointKind::Scope(v) => Box::new(CheckpointSource::Scope(v)),
                        CheckpointKind::Root(v) => Box::new(CheckpointSource::Root(v)),
                        CheckpointKind::Process(v) => Box::new(CheckpointSource::Process(v)),
                        _ => {
                            return Err(error(
                                "SE Code native recovery",
                                "unsupported original checkpoint",
                            ));
                        }
                    };
                    service.checkpoint(
                        auxiliary,
                        CheckpointKind::Exit {
                            source,
                            witness: *witness,
                        },
                    );
                    service.persist(self, deadline).await?;
                }
                RecoveryOutcome::Unproved { error: failure, .. } => {
                    return Err(error("SE Code native recovery unproved", failure));
                }
                RecoveryOutcome::ReleasedOwnership(_) => {
                    return Err(error(
                        "SE Code native recovery",
                        "released ownership does not grant service control",
                    ));
                }
            }
        }
        if service.process.is_none() {
            return Ok(());
        }
        let profile = service.journal.profile.to_local()?;
        let endpoint = if let Some(endpoint) = &service.journal.endpoint {
            endpoint.clone()
        } else {
            if service.journal.initial_offered {
                return Err(error(
                    "SE Code service recovery",
                    "input was attempted without a retained endpoint; preserve pending/no-replay",
                ));
            }
            let path = profile.clone();
            let ready = self
                .store
                .pool
                .run_owned(deadline, move || prepare::ready(&path))
                .await?
                .ok_or_else(|| {
                    error(
                        "SE Code service recovery",
                        "original live service has no readiness receipt",
                    )
                })?;
            let pid = match service.journal.service.as_ref().map(|c| &c.checkpoint) {
                Some(CheckpointKind::Process(record)) => record.root.pid.0,
                _ => {
                    return Err(error(
                        "SE Code service recovery",
                        "original service birth is not published",
                    ));
                }
            };
            if ready["pid"].as_u64() != Some(u64::from(pid)) {
                return Err(error(
                    "SE Code service recovery",
                    "readiness PID differs from the recovered original birth",
                ));
            }
            let endpoint = ready["observed_endpoint"]
                .as_str()
                .ok_or_else(|| error("SE Code service recovery", "readiness endpoint absent"))?
                .to_owned();
            service.journal.endpoint = Some(endpoint.clone());
            service.persist(self, deadline).await?;
            endpoint
        };
        let control = Arc::new(
            self.store
                .pool
                .run_owned(deadline, move || Control::open(&profile, &endpoint))
                .await?,
        );
        if service.journal.identity.is_none() && !service.journal.initial_offered {
            let health = control.read(&["api", "health"], deadline).await?;
            if health.is_null() {
                return Err(error(
                    "SE Code service recovery",
                    "authenticated health is empty",
                ));
            }
            // No original client input was authorized. Retain cleanup control
            // without inventing a qualified session or an input acceptance.
            service.control = Some(control);
            return Ok(());
        }
        let identity = service.journal.identity.as_ref().ok_or_else(|| {
            error(
                "SE Code service recovery",
                "original incarnation was not published",
            )
        })?;
        let binding = control
            .binding(&service.journal.vendor_session, deadline)
            .await?;
        identity.require_same(&binding.service)?;
        let checkpoint = service
            .journal
            .service
            .as_ref()
            .ok_or_else(|| error("SE Code service recovery", "native checkpoint absent"))?;
        if !matches!(checkpoint.checkpoint, CheckpointKind::Process(_)) {
            return Err(error(
                "SE Code service recovery",
                "live process publication absent",
            ));
        }
        service.control = Some(control);
        Ok(())
    }
    pub(in crate::process) async fn restore_secode_work(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if self.observe_secode_service_loss(work, deadline).await? {
            return Ok(());
        }
        let slot = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
            .ok_or_else(|| {
                error(
                    "SE Code client recovery",
                    "original private service journal absent",
                )
            })?;
        let service = lock_service(&slot, deadline).await?;
        if let Some(failure) = &service.failure {
            return Err(error("SE Code client recovery", failure));
        }
        if service.journal.session != work.meta.session
            || (work.activated
                && !matches!(&work.meta.conversation, se_types::Read::Present {value} if value.as_str()==service.journal.vendor_session))
        {
            return Err(error(
                "SE Code client recovery",
                "original engine/vendor session differs",
            ));
        }
        let control = service.control.clone().ok_or_else(|| {
            error(
                "SE Code client recovery",
                "original service is not live and authenticated; preserve pending/no-replay",
            )
        })?;
        let identity = service.journal.identity.clone().ok_or_else(|| {
            error(
                "SE Code client recovery",
                "original service incarnation absent",
            )
        })?;
        let se_proc::CheckpointKind::Process(record) = &service
            .journal
            .service
            .as_ref()
            .ok_or_else(|| {
                error(
                    "SE Code client recovery",
                    "service native checkpoint absent",
                )
            })?
            .checkpoint
        else {
            return Err(error(
                "SE Code client recovery",
                "service process is not live",
            ));
        };
        let observed = control
            .binding(&service.journal.vendor_session, deadline)
            .await?;
        identity.require_same(&observed.service)?;
        let accepted = control
            .acceptance(
                &identity,
                &service.journal.vendor_session,
                &service.journal.initial_input,
                deadline,
            )
            .await?;
        match accepted.data {
            Some(data) => data.require_initial_hash(
                &service.journal.vendor_session,
                &service.journal.initial_input,
                service.journal.initial_sha256,
            )?,
            None if work.activated => {
                return Err(error(
                    "SE Code client recovery",
                    "the activated original input is absent; preserve pending/no-replay",
                ));
            }
            None => (),
        }
        if !work.activated {
            work.meta.conversation = se_types::Read::Present {
                value: se_types::ProviderSessionId::new(service.journal.vendor_session.clone())?,
            };
        }
        work.secode = Some(Prepared {
            control,
            service: identity,
            profile: service.journal.profile.clone(),
            process: native_record::instance(
                &record.root,
                record.argv_sha256,
                &self.options.epoch.owner.fields().boot,
            )?,
            session: service.journal.vendor_session.clone(),
            initial_input: service.journal.initial_input.clone(),
        });
        work.capture_source = Some(se_core::ops::process_commit::session_credential_id(
            &work.meta.session,
            "capture-source",
        )?);
        if let Some(prepared) = work.secode.clone() {
            work.binding = Some(self.secode.recover(prepared));
        }
        Ok(())
    }
}
pub(super) fn recovery_source(source: &CheckpointSource) -> se_proc::RecoverySource {
    match source {
        CheckpointSource::Reservation(v) => {
            se_proc::RecoverySource::Reservation(Box::new(v.clone()))
        }
        CheckpointSource::Scope(v) => se_proc::RecoverySource::Prepared(Box::new(v.clone())),
        CheckpointSource::Root(v) => se_proc::RecoverySource::RootPrepared(Box::new(v.clone())),
        CheckpointSource::Process(v) => se_proc::RecoverySource::Record(Box::new(v.clone())),
    }
}
pub(super) fn inventory(home: &std::path::Path) -> Result<Vec<(PathBuf, Journal, [u8; 32])>> {
    let root = home.join("secode");
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            inventory_slots(home, &[])?;
            return Ok(Vec::new());
        }
        Err(cause) => return Err(error("SE Code custody inventory", cause)),
        Ok(_) => (),
    }
    let _files = se_proc::NativeStateFiles::open(&root)
        .map_err(|e| error("SE Code custody inventory", e))?;
    let entries = std::fs::read_dir(&root).map_err(|e| error("SE Code custody inventory", e))?;
    let mut result = Vec::new();
    for (count, entry) in entries.enumerate() {
        if count >= 4096 {
            return Err(error(
                "SE Code custody inventory",
                "directory exceeds the finite 4096-entry recovery bound; inventory is incomplete",
            ));
        }
        let entry = entry.map_err(|e| error("SE Code custody inventory", e))?;
        let path = entry.path();
        if super::super::files::retain_recovery_artifact(&path)? {
            // Only the published journal can authorize native recovery.
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "json") {
            return Err(error(
                "SE Code custody inventory",
                "unrecognized retained entry; preserve it for owner reconciliation",
            ));
        }
        let (journal, digest) = Journal::read_with_digest(&path)?
            .ok_or_else(|| error("SE Code custody inventory", "listed journal disappeared"))?;
        if Journal::path(home, &journal.project, &journal.agent) != path
            || Journal::profile(home, &journal.project, &journal.agent)
                != journal.profile.to_local()?
        {
            return Err(error(
                "SE Code custody inventory",
                "journal coordinates differ from the protected service path",
            ));
        }
        result.push((path, journal, digest));
    }
    inventory_slots(home, &result)?;
    Ok(result)
}
fn inventory_slots(
    home: &std::path::Path,
    journals: &[(PathBuf, Journal, [u8; 32])],
) -> Result<()> {
    let root = home.join("secode-profiles");
    match std::fs::symlink_metadata(&root) {
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(cause) => return Err(error("SE Code private service slots", cause)),
        Ok(_) => (),
    }
    let _files = se_proc::NativeStateFiles::open(&root)
        .map_err(|e| error("SE Code private service slots", e))?;
    for (count, entry) in std::fs::read_dir(&root)
        .map_err(|e| error("SE Code private service slots", e))?
        .enumerate()
    {
        if count >= 4096 {
            return Err(error(
                "SE Code private service slots",
                "slot inventory exceeds 4096 entries; completeness is unproved",
            ));
        }
        let path = entry
            .map_err(|e| error("SE Code private service slots", e))?
            .path();
        if !journals.iter().any(|(_, journal, _)| {
            Journal::profile(home, &journal.project, &journal.agent).parent()
                == Some(path.as_path())
        }) {
            return Err(error(
                "SE Code private service slots",
                "a retained slot has no published custody journal; preserve it for owner reconciliation",
            ));
        }
        se_proc::NativeStateFiles::open(&path)
            .map_err(|e| error("SE Code private service slot", e))?;
    }
    Ok(())
}
