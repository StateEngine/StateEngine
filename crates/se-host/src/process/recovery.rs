//! Reconcile the protected inventory once, before listener readiness. A bad
//! observation fences its own agent; it never grants a new launch or signal.
mod metadata;
use super::{
    owned::{LifecycleMetadata, Work},
    supervisor::Job,
    *,
};
use crate::client::lease::Deadline;
use se_core::ops::process_commit;
use se_proc::{CheckpointKind, CheckpointSource, ProcessRuntime, RecoveryOutcome, RecoverySource};
use se_store::{Actor, Admission, EventBody, OwnerGuardProcess, ProcessState, Scope, Snapshot};
use se_types::{Read, Result};
use std::sync::{Mutex, atomic::AtomicBool};
use tokio::sync::{Mutex as AsyncMutex, watch};

#[derive(Default)]
pub struct Reconciliation {
    pub adopted: u32,
    pub exited: u32,
    pub unproved: Vec<String>,
}
impl LaunchCoordinator {
    pub(super) async fn restore_cleanup(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        let home = self.options.home.clone();
        let meta = work.meta.clone();
        let reader = self.store.reader.clone();
        let generation = self.store.generation;
        let (pin, files) = self.store.pool.run_owned(deadline, move || {
            if let Some(restored) = files::restore(&home,&meta)? { return Ok((Some(restored.pin),restored.files)); }
            // C1 can precede publication of the cleanup manifest. Only the
            // exact protected pin may have been published in that interval.
            let directory=files::directory(&home,&meta.session)?;
            match std::fs::read_dir(&directory) {
                Ok(entries) => for (count,entry) in entries.enumerate() {
                    let entry=entry.map_err(|e|error("launch cleanup inventory",e))?;
                    if count>=16 || entry.file_name()!="pin" {
                        return Err(error("launch cleanup inventory", "unmanifested files remain; preserve them for owner reconciliation"));
                    }
                },
                Err(e) if e.kind()==std::io::ErrorKind::NotFound => return Ok((None,Vec::new())),
                Err(e) => return Err(error("launch cleanup inventory",e)),
            }
            let state=se_proc::NativeStateFiles::open(&home).map_err(|e|error("retained pin state",e))?;
            if state.readback(&directory.join("pin")).map_err(|e|error("retained pin presence",e))?.is_none() { return Ok((None,Vec::new())); }
            let secret=se_proc::read_session_pin(&state,meta.session.as_str()).map_err(|e|error("retained launch pin",e))?;
            use sha2::{Digest,Sha256};
            let digest=Sha256::digest(secret.expose()).into();
            let phase=reader.read_phase().map_err(|e|se_core::store_error::store_error(&e))?;
            let result=(|| {
                let owner=se_core::scope::require_present(phase.runtime_owner().map_err(|e|se_core::store_error::store_error(&e))?,"pin recovery generation","Keep current writer ownership.")?;
                if owner.generation!=generation { return Err(error("pin recovery generation","owner changed")); }
                let credential=se_core::scope::require_present(phase.credential(digest).map_err(|e|se_core::store_error::store_error(&e))?,"retained session pin","Keep its exact committed credential hash.")?;
                if credential.session!=meta.session || credential.agent!=meta.agent.id || credential.project!=meta.project.id || credential.purpose!="session" { return Err(error("retained pin credential","identity differs")); }
                Ok((Some(digest),Vec::new()))
            })();
            crate::runtime::executor::close_read(result,phase.close())
        }).await?;
        work.pin_hash = pin;
        work.files = files;
        work.cleanup_files_known = true;
        Ok(())
    }
    /// The caller must pass the inventory taken from HostedRuntime after the
    /// writer and this executor have been installed, and before serving.
    pub async fn reconcile(
        self: &Arc<Self>,
        inventory: Vec<OwnerGuardProcess>,
        deadline: &Deadline,
    ) -> Result<Reconciliation> {
        let mut report = Reconciliation::default();
        for retained in inventory {
            let admission = Admission {
                scope: Scope::Project(retained.project.clone()),
                actor: Actor::Human(self.human.clone()),
                session: None,
                generation: self.store.generation.get(),
            };
            let lifecycle = retained.identity.record.clone();
            // Read the exact immutable source under the new owner, rather than
            // converting the boot inventory itself into authority.
            let id = lifecycle.clone();
            let previous = self
                .store
                .read(admission.clone(), deadline, move |cx| {
                    se_core::scope::require_present(
                        cx.read
                            .process(id)
                            .map_err(|e| se_core::store_error::store_error(&e))?,
                        "retained process",
                        "Keep its recorded identity for owner reconciliation.",
                    )
                })
                .await?;
            if previous.revision != retained.revision {
                return Err(se_core::scope::unreadable(
                    "startup custody",
                    "inventory revision changed before reconciliation",
                ));
            }
            let decoded = se_proc::decode_checkpoint(
                retained.identity.custody.format_version,
                &retained.identity.custody.record,
            )
            .map_err(|e| error("startup native checkpoint", e));
            let outcome = match decoded.and_then(|value| recovery_source(value, &retained)) {
                Ok(source) => {
                    let native = self.native.clone();
                    let generation = self.options.epoch.generation;
                    self.store
                        .pool
                        .run_owned(deadline, move || {
                            let plan = native
                                .plan_recovery(source)
                                .map_err(|e| error("native recovery plan", e))?;
                            native
                                .recover(plan, generation)
                                .map_err(|e| error("native custody recovery", e))
                        })
                        .await
                }
                Err(error) => Err(error),
            };
            // A committed exit is terminal. A failed or contradictory new probe
            // leaves cleanup debt; it cannot resurrect the process through Lost.
            if retained.state == ProcessState::Exited
                && !matches!(&outcome, Ok(RecoveryOutcome::Exited(_)))
            {
                let reason = match &outcome {
                    Err(error) => error.to_string(),
                    Ok(RecoveryOutcome::Unproved { error, .. }) => format!("{error:?}"),
                    _ => "native outcome does not confirm the committed exit".into(),
                };
                let credential_debt = retained
                    .identity
                    .session
                    .as_ref()
                    .map(|session| {
                        format!(
                            "session {session}: session/http credential revocation remains unproved"
                        )
                    })
                    .unwrap_or_else(|| {
                        "session binding absent; credential cleanup scope is unknown".into()
                    });
                self.retain_orphan(&lifecycle)?;
                report.unproved.push(format!(
                    "{lifecycle}: committed exit retained; cleanup unproved: {reason}; {credential_debt}"
                ));
                continue;
            }
            let metadata = self
                .recovery_metadata(&retained, admission.clone(), deadline)
                .await;
            let mut work = match metadata {
                Ok((meta, active, retired, activated)) => {
                    let mut work = Work::recovered(meta, admission.clone());
                    work.active = active;
                    work.activated = activated;
                    work.session_retired = retired;
                    work
                }
                Err(error) => {
                    self.mark_recovery_unproved(
                        previous,
                        retained.identity,
                        error.to_string(),
                        admission,
                        deadline,
                    )
                    .await?;
                    self.retain_orphan(&lifecycle)?;
                    report
                        .unproved
                        .push(format!("{lifecycle}: metadata unavailable: {error}"));
                    continue;
                }
            };
            if let Err(error) = self.restore_cleanup(&mut work, deadline).await {
                work.cleanup_failure = Some(error.body);
            }
            match outcome {
                Ok(RecoveryOutcome::Recovered { process, record }) => {
                    let process = Arc::new(process);
                    let native = self.native.clone();
                    let owned = process.clone();
                    let wake = work.wake.clone();
                    let watch = self
                        .store
                        .pool
                        .run_owned(deadline, move || {
                            native
                                .watch_exit(&owned, wake)
                                .map_err(|e| error("recovered exit subscription", e))
                        })
                        .await;
                    let watch_failure = match watch {
                        Ok(watch) => {
                            work.exit_watch = Some(watch);
                            None
                        }
                        Err(error) => Some(error),
                    };
                    work.process = Some(process);
                    work.record = Some((*record).clone());
                    work.exec_observed = true;
                    let root = record.root.clone();
                    let at = deadline.at();
                    match self
                        .store
                        .pool
                        .run_owned(deadline, move || super::launch_util::view(&root, at))
                        .await
                    {
                        Ok(view) => work.process_view = Some(view),
                        Err(error) => work.cleanup_failure = Some(error.body),
                    }

                    let mut failure = watch_failure;
                    if !work.active
                        && !work.session_retired
                        && let Err(error) = self
                            .retire_session(
                                &mut work,
                                "prepared launch interrupted before C3",
                                deadline,
                            )
                            .await
                    {
                        failure = Some(error);
                    }
                    if let Some(error) = &failure {
                        report.unproved.push(format!("{lifecycle}: {error}"));
                        work.cleanup_failure = Some(error.body.clone());
                    }
                    let target = if failure.is_some()
                        || matches!(
                            retained.state,
                            ProcessState::StopRequested | ProcessState::StopUnproved
                        ) {
                        ProcessState::StopUnproved
                    } else {
                        ProcessState::Running
                    };
                    let identity = native_record::identity_meta(
                        &work.meta,
                        CheckpointKind::Process(*record.clone()),
                        Some((&record.root, record.argv_sha256)),
                        Some(record.guarantee),
                        &self.options.epoch.owner.fields().boot,
                    )?;
                    self.store
                        .commit(admission, deadline, None, move |kernel, cx| {
                            process_commit::reconcile(
                                kernel,
                                previous,
                                identity,
                                target,
                                "successor host verified and retained native custody".into(),
                                cx,
                            )
                        })
                        .await?;
                    let job = self.retain_recovered(work)?;
                    if failure.is_none() {
                        let coordinator = self.clone();
                        let owned = job.clone();
                        let task = self.store.pool.handle().spawn(async move {
                            coordinator.monitor_protected(owned).await;
                        });
                        *job.task
                            .lock()
                            .map_err(|_| error("recovered monitor", "poisoned task slot"))? =
                            Some(task);
                    }
                    report.adopted = report.adopted.saturating_add(1);
                }
                Ok(RecoveryOutcome::Exited(witness)) => {
                    work.native_already_reconciled = true;
                    work.last_witness = Some((*witness).clone());
                    work.stop_method = Some("native-reconciliation".into());
                    match self.finish(&mut work, *witness, deadline).await {
                        Ok(()) => report.exited = report.exited.saturating_add(1),
                        Err(error) => {
                            work.cleanup_failure = Some(error.body.clone());
                            report.unproved.push(format!(
                                "{lifecycle}: native exit proved; cleanup incomplete: {error}"
                            ));
                            self.retain_recovered(work)?;
                        }
                    }
                }
                other => {
                    let reason = match other {
                        Ok(RecoveryOutcome::Unproved { error, .. }) => format!("StopUnproved: {error:?}"),
                        Ok(RecoveryOutcome::PendingScope { process, .. }) => {
                            work.process = Some(Arc::new(process));
                            "StopUnproved: native scope recovered without a published provider root".into()
                        }
                        Ok(RecoveryOutcome::ReleasedOwnership(_)) => "StopUnproved: recorded ownership was released; no signal authority was acquired".into(),
                        Err(error) => format!("StopUnproved: native observation unavailable: {error}"),
                        Ok(RecoveryOutcome::Recovered { .. } | RecoveryOutcome::Exited(_)) => unreachable!(),
                    };
                    self.mark_recovery_unproved(
                        previous,
                        retained.identity,
                        reason.clone(),
                        admission,
                        deadline,
                    )
                    .await?;
                    let mut reason = reason;
                    if !work.active
                        && !work.session_retired
                        && let Err(failure) = self
                            .retire_session(
                                &mut work,
                                "prepared launch interrupted before C3",
                                deadline,
                            )
                            .await
                    {
                        reason
                            .push_str(&format!("; prepared credential cleanup remains: {failure}"));
                    }
                    work.cleanup_failure =
                        Some(se_core::scope::unreadable("retained native custody", &reason).body);
                    self.retain_recovered(work)?;
                    report.unproved.push(format!("{lifecycle}: {reason}"));
                }
            }
        }
        Ok(report)
    }
    fn retain_orphan(&self, lifecycle: &se_types::LifecycleId) -> Result<()> {
        let mut orphans = self
            .orphans
            .lock()
            .map_err(|_| super::error("orphan custody", "poisoned registry"))?;
        if orphans.insert(lifecycle.clone()) {
            self.activity
                .send_modify(|count| *count = count.saturating_add(1));
        }
        Ok(())
    }
    async fn mark_recovery_unproved(
        &self,
        previous: se_store::ProjectionRecord,
        identity: se_store::ProcessIdentityRecord,
        reason: String,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        // Session metadata failure also leaves a witnessed exit intact.
        if matches!(
            &previous.current.body,
            EventBody::ProcessTransition {
                to: ProcessState::Exited,
                ..
            }
        ) {
            return Ok(());
        }
        self.store
            .commit(admission, deadline, None, move |kernel, cx| {
                process_commit::reconcile(
                    kernel,
                    previous,
                    identity,
                    ProcessState::StopUnproved,
                    reason,
                    cx,
                )
            })
            .await?;
        Ok(())
    }
    pub(super) fn retain_recovered(&self, work: Work) -> Result<Arc<Job>> {
        let key = format!("recovered/{}", work.meta.lifecycle);
        let wake = work.wake.clone();
        let job = Arc::new(Job {
            fault: std::sync::Mutex::new(None),
            intent: [0; 32],
            target: (work.meta.project.id.clone(), work.meta.agent.id.clone()),
            lifecycle: work.meta.lifecycle.clone(),
            state: AsyncMutex::new(work),
            ready: watch::channel(None).0,
            settled: AtomicBool::new(false),
            mail_pending: AtomicBool::new(true),
            wake,
            task: Mutex::new(None),
        });
        let mut jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("recovered custody registry", "poisoned"))?;
        if jobs.contains_key(&key) {
            return Err(error("recovered lifecycle", "already retained"));
        }
        jobs.insert(key, job.clone());
        let was_orphan = self
            .orphans
            .lock()
            .map_err(|_| super::error("orphan custody", "poisoned registry"))?
            .remove(&job.lifecycle);
        if !was_orphan {
            self.activity
                .send_modify(|count| *count = count.saturating_add(1));
        }
        Ok(job)
    }
}
pub(super) fn recovery_source(
    checkpoint: se_proc::Checkpoint,
    retained: &OwnerGuardProcess,
) -> Result<RecoverySource> {
    if checkpoint.lifecycle != retained.identity.record
        || checkpoint.session != retained.identity.session
        || !matches!((&checkpoint.principal, &retained.identity.principal), (se_proc::CheckpointPrincipal::Agent(a),Actor::Agent(b)) if a==b)
    {
        return Err(error(
            "startup custody codec",
            "principal/session/lifecycle differs from protected index",
        ));
    }
    Ok(match checkpoint.checkpoint {
        CheckpointKind::Reservation(v) => RecoverySource::Reservation(Box::new(v)),
        CheckpointKind::Scope(v) => RecoverySource::Prepared(Box::new(v)),
        CheckpointKind::Root(v) => RecoverySource::RootPrepared(Box::new(v)),
        CheckpointKind::Process(v) => RecoverySource::Record(Box::new(v)),
        CheckpointKind::Exit { source, .. } => match *source {
            CheckpointSource::Reservation(v) => RecoverySource::Reservation(Box::new(v)),
            CheckpointSource::Scope(v) => RecoverySource::Prepared(Box::new(v)),
            CheckpointSource::Root(v) => RecoverySource::RootPrepared(Box::new(v)),
            CheckpointSource::Process(v) => RecoverySource::Record(Box::new(v)),
        },
        _ => {
            return Err(error(
                "startup custody codec",
                "unsupported terminal or historical checkpoint",
            ));
        }
    })
}
