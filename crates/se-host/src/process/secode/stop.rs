//! Client cancellation and authenticated execution settlement are separate from
//! service retirement. A native exit alone never closes a vendor execution.
use super::*;
use se_proc::ProcessRuntime;
use serde_json::{Value, json};

impl LaunchCoordinator {
    pub(in crate::process) async fn interrupt_secode_client(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let process = work.process.clone().ok_or_else(|| {
            error(
                "SE Code client cancellation",
                "retained native process absent",
            )
        })?;
        let native = self.native.clone();
        let at = deadline.at();
        let generation = self.options.epoch.generation;
        self.store
            .pool
            .run_owned(deadline, move || {
                let prepared = native
                    .prepare_stop(&process, generation, at)
                    .map_err(|e| error("SE Code native interrupt preparation", e))?;
                native
                    .request_interrupt(prepared)
                    .map_err(|e| error("SE Code native interrupt", e))?
                    .dispatch
                    .map_err(|e| error("SE Code native interrupt dispatch", e))?;
                Ok(())
            })
            .await
    }
    pub(in crate::process) async fn settle_secode(
        &self,
        work: &mut owned::Work,
        witness: &se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        if !work.force_relaunch {
            return self.settle_secode_inner(work, witness, deadline).await;
        }
        let graceful = deadline.stage(std::time::Duration::from_secs(3))?;
        match self.settle_secode_inner(work, witness, &graceful).await {
            Ok(()) => return Ok(()),
            Err(failure) => work.stop_failure = Some(failure.body),
        }
        // A service's stale execution flags do not outrank its exact native
        // custody. Retire that one private service, never a shared provider.
        self.force_retire_secode_service(work, deadline).await
    }

    async fn settle_secode_inner(
        &self,
        work: &mut owned::Work,
        witness: &se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        if self.observe_secode_service_loss(work, deadline).await? {
            return Ok(());
        }
        let Some(managed) = work.secode.clone() else {
            if matches!(witness.root, se_proc::RootWitness::NoChildCreated)
                || (work.session_retired && work.capture_flushed)
            {
                return Ok(());
            }
            return Err(error(
                "SE Code execution settlement",
                "original authenticated service control is unavailable; client exit alone cannot close vendor execution or capture",
            ));
        };
        let binding = managed.control.binding(&managed.session, deadline).await?;
        managed.service.require_same(&binding.service)?;
        managed
            .control
            .request(
                reqwest::Method::POST,
                &["api", "session", &managed.session, "interrupt"],
                Some(&json!({})),
                deadline,
            )
            .await?;
        let held = managed.control.binding(&managed.session, deadline).await?;
        managed.service.require_same(&held.service)?;
        if held.status == crate::harness::secode_process::NoticeStatus::Ready {
            return Err(error(
                "SE Code execution settlement",
                "native mail is not held",
            ));
        }
        if !matches!(witness.root, se_proc::RootWitness::NoChildCreated) {
            let accepted = managed
                .control
                .acceptance(
                    &managed.service,
                    &managed.session,
                    &managed.initial_input,
                    deadline,
                )
                .await?;
            let Some(accepted) = accepted.data else {
                return Err(error(
                    "SE Code original input",
                    "client is absent but original admission remains null; retain pending/no-replay",
                ));
            };
            let slot = self
                .secode_services
                .get(&work.meta.project.id, &work.meta.agent.id, deadline)
                .await?
                .ok_or_else(|| error("SE Code input reconciliation", "private custody absent"))?;
            let service = lock_service(&slot, deadline).await?;
            accepted.require_initial_hash(
                &managed.session,
                &managed.initial_input,
                service.journal.initial_sha256,
            )?;
        }
        loop {
            let active = managed
                .control
                .read(&["api", "session", "active"], deadline)
                .await?;
            let active = active["data"]
                .as_object()
                .ok_or_else(|| error("SE Code active executions", "complete session map absent"))?;
            if !active.contains_key(&managed.session) {
                break;
            }
            tokio::time::sleep(
                deadline
                    .remaining()?
                    .min(std::time::Duration::from_millis(25)),
            )
            .await;
        }
        managed
            .control
            .request(
                reqwest::Method::POST,
                &["api", "session", &managed.session, "reconcile"],
                Some(&json!({})),
                deadline,
            )
            .await?;
        let after = managed.control.binding(&managed.session, deadline).await?;
        managed.service.require_same(&after.service)?;
        Ok(())
    }
    pub(in crate::process) async fn shutdown_secode(
        &self,
        deadline: &Deadline,
    ) -> Result<Vec<String>> {
        if let Some(failure) = self
            .secode_services
            .1
            .lock()
            .map_err(|_| error("SE Code custody inventory", "poisoned inventory state"))?
            .as_ref()
        {
            return Ok(vec![format!(
                "SE Code service inventory remains unproved: {failure}"
            )]);
        }
        let services = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.at()),
            self.secode_services.0.lock(),
        )
        .await
        .map_err(|_| error("SE Code service shutdown", "a retained preparation is busy"))?;
        let slots = services.values().cloned().collect::<Vec<_>>();
        drop(services);
        let mut stopping = slots.iter().map(|slot| async {
                let mut service = lock_service(slot, deadline).await?;
                if self.find_job(&service.journal.project, &service.journal.agent)?.is_some_and(|job| !job.settled.load(std::sync::atomic::Ordering::Acquire)) {
                    return Err(error("SE Code service shutdown", "original client or capture cleanup remains pending; service retained"));
                }
                if service.journal.lost {
                    return self.retire_lost_secode_service(&mut service, deadline).await;
                }
                if service.journal.initial_offered
                    && !service.journal.client_closed.as_ref().is_some_and(|closed| closed.capture_complete)
                {
                    return Err(error("SE Code service shutdown", "original input or final capture remains unresolved; its authenticated source service is retained"));
                }
                for auxiliary in Auxiliary::ALL {
                    if service.owner(auxiliary).is_none()
                        && service.journal.auxiliary(auxiliary).as_ref().is_some_and(|checkpoint|
                            !matches!(checkpoint.checkpoint, se_proc::CheckpointKind::Exit { .. })) {
                        self.recover_secode_auxiliary(&mut service, auxiliary, deadline).await?;
                    }
                }
                // A service may have died after final client capture. Prove
                // its native scope closed before skipping the dead endpoint;
                // failed HTTP alone never grants registration retirement.
                if let Some(owner) = service.process.clone() {
                    let native = self.native.clone();
                    let observed = self.store.pool.run_owned(deadline, move || {
                        native.witness_exit(&owner).map_err(|e| error("SE Code service exit", e))
                    }).await?;
                    if let se_proc::StopObservation::Complete(witness) = observed {
                        self.retire_secode_auxiliary(&mut service, Auxiliary::Service, &witness, deadline).await?;
                    }
                }
                if let Some(control) = service.control.as_ref().filter(|_| service.process.is_some()) {
                    let active = control.read(&["api","session","active"], deadline).await?;
                    match active.get("data").and_then(Value::as_object) {
                        Some(rows) if rows.is_empty() => (),
                        _ => return Err(error("SE Code service shutdown", "active execution inventory is nonempty or unreadable; service retained")),
                    }
                }
                for auxiliary in Auxiliary::ALL {
                    let live = service.owner(auxiliary).is_some();
                    if !live { continue; }
                    let graceful = deadline.stage(std::time::Duration::from_secs(5))?;
                    if let Err(original) = self.stop_secode_auxiliary(&mut service, auxiliary, false, &graceful).await {
                        service.journal.stop_failure = Some(format!("Graceful auxiliary shutdown was unconfirmed; native forced fallback requested: {original}"));
                        service.persist(self, deadline).await?;
                        self.stop_secode_auxiliary(&mut service, auxiliary, true, deadline).await.map_err(|force| force.with_cause(original))?;
                    }
                }
                for checkpoint in Auxiliary::ALL.into_iter().filter_map(|key| service.journal.auxiliary(key).as_ref()) {
                    if !matches!(&checkpoint.checkpoint, se_proc::CheckpointKind::Exit { witness, .. } if witness.scope_exit.exit_basis.is_some()) {
                        return Err(error("SE Code service retirement", "an original auxiliary checkpoint has no native empty-scope witness; missing retained handles are not absence"));
                    }
                }
                self.retire_secode_registration(&mut service, deadline).await?;
                let profile = service.journal.profile.to_local()?;
                self.store.pool.run_owned(deadline, move || {
                    match std::fs::symlink_metadata(&profile) {
                        Err(cause) if cause.kind()==std::io::ErrorKind::NotFound => return Ok(()),
                        Err(cause) => return Err(error("SE Code service profile retirement",cause)),
                        Ok(_) => (),
                    }
                    let _files = se_proc::NativeProfileFiles::open(&profile).map_err(|e| error("SE Code service retirement", e))?;
                    // Registration is non-secret vendor metadata beneath the
                    // protected private profile; its public file mode need not
                    // match the host's owner-only credential mode.
                    if se_proc::NativeSourcePin::open(&profile.join("registration")).map_err(|e| error("SE Code registration retirement", e))?.is_some() { return Err(error("SE Code service retirement", "native processes exited but registration is still present; preserve the private profile for reconciliation")); }
                    Ok(())
                }).await?;
                service.journal.retired=true;
                service.persist(self,deadline).await
        }).collect::<futures_util::stream::FuturesUnordered<_>>();
        use futures_util::StreamExt;
        let mut pending = Vec::new();
        while let Some(result) = stopping.next().await {
            if let Err(error) = result {
                pending.push(format!("SE Code private service: {error}"));
            }
        }
        Ok(pending)
    }
}
