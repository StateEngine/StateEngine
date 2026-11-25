//! Reconcile the protected inventory once, before listener readiness. A bad
//! observation fences its own agent; it never grants a new launch or signal.
mod metadata;
mod provider;
use super::{
    owned::{LifecycleMetadata, Work},
    supervisor::Job,
    *,
};
use crate::client::lease::Deadline;
use se_core::ops::process_commit;
use se_core::scope::{require_present, unreadable};
use se_proc::{CheckpointKind, ProcessRuntime, RecoveryOutcome};
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
struct RecoveredProcess {
    previous: se_store::ProjectionRecord,
    process: se_proc::OwnedProcess,
    record: Box<se_proc::ProcessRecord>,
    state: ProcessState,
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
                    if count>=16 {
                        return Err(error("launch cleanup inventory", "finite recovery bound exceeded; preserve the original inventory"));
                    }
                    if entry.file_name()!="pin" && !files::retain_recovery_artifact(&entry.path())? {
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
        work.pin_file_hash = pin;
        work.files = files;
        work.cleanup_files_known = true;
        Ok(())
    }
    fn spawn_monitor(self: &Arc<Self>, job: &Arc<Job>, subject: &'static str) -> Result<()> {
        let (coordinator, owned) = (self.clone(), job.clone());
        let task = self.store.pool.handle().spawn(async move {
            coordinator.monitor_protected(owned).await;
        });
        *job.task
            .lock()
            .map_err(|_| error(subject, "poisoned task slot"))? = Some(task);
        Ok(())
    }
    fn record_exited_debt(
        &self,
        retained: &OwnerGuardProcess,
        outcome: &Result<RecoveryOutcome>,
        report: &mut Reconciliation,
    ) -> Result<()> {
        let lifecycle = &retained.identity.record;
        let reason = match outcome {
            Err(error) => error.to_string(),
            Ok(RecoveryOutcome::Unproved { error, .. }) => format!("{error:?}"),
            _ => "native outcome does not confirm the committed exit".into(),
        };
        let credential_debt = retained
            .identity
            .session
            .as_ref()
            .map(|session| {
                format!("session {session}: session/http credential revocation remains unproved")
            })
            .unwrap_or_else(|| {
                "session binding absent; credential cleanup scope is unknown".into()
            });
        self.retain_orphan(lifecycle)?;
        report.unproved.push(format!(
            "{lifecycle}: committed exit retained; cleanup unproved: {reason}; {credential_debt}"
        ));
        Ok(())
    }
    async fn adopt_recovered(
        self: &Arc<Self>,
        mut work: Work,
        recovered: RecoveredProcess,
        deadline: &Deadline,
        report: &mut Reconciliation,
    ) -> Result<()> {
        let lifecycle = work.meta.lifecycle.clone();
        let process = Arc::new(recovered.process);
        let (native, owned, wake) = (self.native.clone(), process.clone(), work.wake.clone());
        let watch_failure = match self
            .on_pool(deadline, move || {
                native
                    .watch_exit(&owned, wake)
                    .map_err(|e| error("recovered exit subscription", e))
            })
            .await
        {
            Ok(watch) => {
                work.exit_watch = Some(watch);
                None
            }
            Err(error) => Some(error),
        };
        work.process = Some(process);
        work.record = Some((*recovered.record).clone());
        work.exec_observed = true;
        let (root, at) = (recovered.record.root.clone(), deadline.at());
        match self
            .on_pool(deadline, move || super::launch_util::view(&root, at))
            .await
        {
            Ok(view) => work.process_view = Some(view),
            Err(error) => work.cleanup_failure = Some(error.body),
        }
        let mut failure = watch_failure;
        if let Err(error) = self.retire_unactivated(&mut work, deadline).await {
            failure = Some(error);
        }
        if let Some(error) = &failure {
            report.unproved.push(format!("{lifecycle}: {error}"));
            work.cleanup_failure = Some(error.body.clone());
        }
        let stopping = matches!(
            recovered.state,
            ProcessState::StopRequested | ProcessState::StopUnproved
        );
        let target = if failure.is_some() || stopping {
            ProcessState::StopUnproved
        } else {
            ProcessState::Running
        };
        let identity = native_record::identity_meta(
            &work.meta,
            CheckpointKind::Process(*recovered.record.clone()),
            Some((&recovered.record.root, recovered.record.argv_sha256)),
            Some(recovered.record.guarantee),
            &self.options.epoch.owner.fields().boot,
        )?;
        self.commit_reconcile(
            recovered.previous,
            identity,
            target,
            "successor host verified and retained native custody".into(),
            work.admission.clone(),
            deadline,
        )
        .await?;
        work.recover_provider =
            failure.is_none() && work.active && !work.session_retired && !stopping;
        let job = self.retain_recovered(work)?;
        if failure.is_none() {
            self.spawn_monitor(&job, "recovered monitor")?;
        }
        report.adopted = report.adopted.saturating_add(1);
        Ok(())
    }
    async fn retire_unactivated(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        if !work.active && !work.session_retired {
            self.retire_session(work, "prepared launch interrupted before C3", deadline)
                .await?;
        }
        Ok(())
    }
    async fn restore_work_state(&self, work: &mut Work, deadline: &Deadline) {
        if let Err(error) = self.restore_capture_status(work, deadline).await {
            work.capture_failure = Some(error.body);
        }
        if let Err(error) = self.restore_cleanup(work, deadline).await {
            work.cleanup_failure = Some(error.body);
        }
        if work.meta.provider == se_store::Provider::SeCode
            && let Err(error) = self.restore_secode_work(work, deadline).await
        {
            work.cleanup_failure = Some(error.body);
        }
    }
    async fn load_retained_process(
        &self,
        retained: &OwnerGuardProcess,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<(se_store::ProjectionRecord, Result<RecoveryOutcome>)> {
        let id = retained.identity.record.clone();
        let previous = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                require_present(
                    cx.read.process(id).map_err(store_error)?,
                    "retained process",
                    "Keep its recorded identity for owner reconciliation.",
                )
            })
            .await?;
        if previous.revision != retained.revision {
            return Err(unreadable(
                "startup custody",
                "inventory revision changed before reconciliation",
            ));
        }
        let outcome = match se_proc::decode_checkpoint(
            retained.identity.custody.format_version,
            &retained.identity.custody.record,
        )
        .map_err(|e| error("startup native checkpoint", e))
        {
            Ok(checkpoint) => self.observe_recovery(checkpoint, retained, deadline).await,
            Err(error) => Err(error),
        };
        Ok((previous, outcome))
    }
    async fn reconcile_one(
        self: &Arc<Self>,
        retained: OwnerGuardProcess,
        deadline: &Deadline,
        report: &mut Reconciliation,
    ) -> Result<()> {
        let admission = Admission {
            scope: Scope::Project(retained.project.clone()),
            actor: Actor::Human(self.human.clone()),
            session: None,
            generation: self.store.generation.get(),
        };
        let lifecycle = retained.identity.record.clone();
        // Read the exact immutable source under the new owner, rather than
        // converting the boot inventory itself into authority.
        let (previous, outcome) = self
            .load_retained_process(&retained, &admission, deadline)
            .await?;
        // A committed exit is terminal. A failed or contradictory new probe
        // leaves cleanup debt; it cannot resurrect the process through Lost.
        if retained.state == ProcessState::Exited
            && !matches!(&outcome, Ok(RecoveryOutcome::Exited(_)))
        {
            return self.record_exited_debt(&retained, &outcome, report);
        }
        let mut work = match self
            .recovery_metadata(&retained, admission.clone(), deadline)
            .await
        {
            Ok((meta, active, retired, activated)) => {
                let mut work = Work::recovered(meta, admission.clone());
                (work.active, work.activated, work.session_retired) = (active, activated, retired);
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
                return Ok(());
            }
        };
        self.restore_work_state(&mut work, deadline).await;
        let mut reason = match outcome {
            Ok(RecoveryOutcome::Recovered { process, record }) => {
                let recovered = RecoveredProcess {
                    previous,
                    process,
                    record,
                    state: retained.state,
                };
                return self
                    .adopt_recovered(work, recovered, deadline, report)
                    .await;
            }
            Ok(RecoveryOutcome::Exited(witness)) => {
                work.native_already_reconciled = true;
                work.last_witness = Some((*witness).clone());
                work.stop_method =
                    Some(crate::reboot::exit_reason(&witness, "native-reconciliation").into());
                // Trusted capture opens at listener publication. Keep the
                // exited lifecycle until its monitor can capture the tail;
                // startup must not retire it behind the readiness fence.
                let job = self.retain_recovered(work)?;
                self.spawn_monitor(&job, "recovered exit monitor")?;
                report.exited = report.exited.saturating_add(1);
                return Ok(());
            }
            Ok(RecoveryOutcome::Unproved { error, .. }) => format!("StopUnproved: {error:?}"),
            Ok(RecoveryOutcome::PendingScope { process, .. }) => {
                work.process = Some(Arc::new(process));
                "StopUnproved: native scope recovered without a published provider root".into()
            }
            Ok(RecoveryOutcome::ReleasedOwnership(_)) => {
                "StopUnproved: recorded ownership was released; no signal authority was acquired"
                    .into()
            }
            Err(error) => format!("StopUnproved: native observation unavailable: {error}"),
        };
        self.mark_recovery_unproved(
            previous,
            retained.identity,
            reason.clone(),
            admission,
            deadline,
        )
        .await?;
        if let Err(failure) = self.retire_unactivated(&mut work, deadline).await {
            reason.push_str(&format!("; prepared credential cleanup remains: {failure}"));
        }
        work.cleanup_failure =
            Some(se_core::scope::unreadable("retained native custody", &reason).body);
        self.retain_recovered(work)?;
        report.unproved.push(format!("{lifecycle}: {reason}"));
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
            self.reconcile_one(retained, deadline, &mut report).await?;
        }
        Ok(report)
    }
    /// The reboot-aware recovery decision, run on the worker pool.
    pub(super) async fn observe_recovery(
        &self,
        checkpoint: se_proc::Checkpoint,
        retained: &OwnerGuardProcess,
        deadline: &Deadline,
    ) -> Result<RecoveryOutcome> {
        let (native, machine) = (self.native.clone(), self.owner.machine.clone());
        let (generation, retained) = (self.options.epoch.generation, retained.clone());
        let job =
            move || crate::reboot::recover(&native, machine, generation, checkpoint, &retained);
        self.store.pool.run_owned(deadline, job).await
    }
    fn retain_orphan(&self, lifecycle: &se_types::LifecycleId) -> Result<()> {
        let mut orphans = self
            .orphans
            .lock()
            .map_err(|_| super::error("orphan custody", "poisoned registry"))?;
        if orphans.insert(lifecycle.clone()) {
            self.inc_activity();
        }
        Ok(())
    }
    async fn commit_reconcile(
        &self,
        previous: se_store::ProjectionRecord,
        identity: se_store::ProcessIdentityRecord,
        target: ProcessState,
        reason: String,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        self.store
            .commit(admission, deadline, None, move |kernel, cx| {
                process_commit::reconcile(kernel, previous, identity, target, reason, cx)
            })
            .await?;
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
        self.commit_reconcile(
            previous,
            identity,
            ProcessState::StopUnproved,
            reason,
            admission,
            deadline,
        )
        .await
    }
    pub(super) fn retain_recovered(&self, work: Work) -> Result<Arc<Job>> {
        let key = format!("recovered/{}", work.meta.lifecycle);
        let wake = work.wake.clone();
        let job = Arc::new(Job {
            ended_by_reboot: work
                .last_witness
                .as_ref()
                .is_some_and(se_proc::StopWitness::ended_by_reboot),
            fault: std::sync::Mutex::new(work.recover_provider.then(|| {
                format!(
                    "Restoring {:?} provider control for agent {} ({}) in its original session {}",
                    work.meta.provider, work.meta.agent.name, work.meta.agent.id, work.meta.session
                )
            })),
            intent: [0; 32],
            target: (work.meta.project.id.clone(), work.meta.agent.id.clone()),
            session: work.meta.session.clone(),
            lifecycle: work.meta.lifecycle.clone(),
            provider: work.meta.provider,
            plan: None,
            takeover: None,
            state: AsyncMutex::new(work),
            ready: watch::channel(None).0,
            settled: AtomicBool::new(false),
            mail_pending: AtomicBool::new(true),
            mail_reoffer: AtomicBool::new(false),
            capture_pending: AtomicBool::new(false),
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
            self.inc_activity();
        }
        Ok(job)
    }
}
