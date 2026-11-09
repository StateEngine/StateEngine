//! A cold stop must re-observe recorded exit; absence of a warm supervisor is
//! never its witness. Explicit released ownership remains unwitnessed.
use super::{owned::Work, supervisor::Job, *};
use crate::client::lease::Deadline;
use se_store::{
    Actor, Admission, ControlTarget, EventBody, OwnerGuardProcess, ProcessState, Scope,
};
use se_types::{Read, Result};
use std::sync::atomic::Ordering;
impl LaunchCoordinator {
    pub(super) async fn cold_stop_job(
        self: &Arc<Self>,
        control: &ControlTarget,
        project: &se_types::ProjectId,
        deadline: &Deadline,
    ) -> Result<Option<Arc<Job>>> {
        let head = match &control.latest_process {
            Read::Present { value } => value.clone(),
            Read::Absent { .. } => return Ok(None),
            Read::Unreadable { reason, .. } => return Err(error("cold stop inventory", reason)),
            Read::Unknown { what } => return Err(error("cold stop inventory", what)),
        };
        let (identity, state) = match &head.current.body {
            EventBody::ProcessRegistered { identity, initial } => {
                (identity.as_ref().clone(), *initial)
            }
            EventBody::ProcessTransition { identity, to, .. } => (identity.as_ref().clone(), *to),
            _ => return Err(error("cold stop inventory", "wrong process projection")),
        };
        let target = match &identity.principal {
            Actor::Agent(agent) => agent.clone(),
            _ => return Err(error("cold stop inventory", "not an agent lifecycle")),
        };
        let row = OwnerGuardProcess {
            project: project.clone(),
            revision: head.revision,
            state,
            identity,
        };
        let admission = Admission {
            scope: Scope::Project(project.clone()),
            actor: Actor::Human(self.human.clone()),
            session: None,
            generation: self.store.generation.get(),
        };
        let checkpoint = se_proc::decode_checkpoint(
            row.identity.custody.format_version,
            &row.identity.custody.record,
        )
        .map_err(|e| error("cold stop checkpoint", e))?;
        let released = match &checkpoint.checkpoint {
            se_proc::CheckpointKind::Released { release, .. } => Some(release.clone()),
            se_proc::CheckpointKind::Process(record) => record.ownership_release.clone(),
            _ => None,
        };
        if released.is_none() && state != ProcessState::Exited {
            self.reconcile(vec![row], deadline).await?;
            return self.find_job(project, &target);
        }
        let (meta, active, retired, activated) = self
            .recovery_metadata(&row, admission.clone(), deadline)
            .await?;
        let mut work = Work::recovered(meta, admission);
        work.active = active;
        work.activated = activated;
        work.session_retired = retired;
        if let Some(release) = released {
            work.ownership_release = Some(release);
            work.released = true;
            let job = self.retain_recovered(work)?;
            job.settled.store(true, Ordering::Release);
            self.activity
                .send_modify(|count| *count = count.saturating_sub(1));
            return Ok(Some(job));
        }
        self.restore_capture_status(&mut work, deadline).await?;
        if work.meta.provider == se_store::Provider::SeCode
            && !(work.session_retired && work.capture_flushed)
        {
            self.restore_secode_work(&mut work, deadline).await?;
        }
        let source = super::recovery::recovery_source(checkpoint, &row)?;
        let native = self.native.clone();
        let generation = self.options.epoch.generation;
        let outcome = self
            .store
            .pool
            .run_owned(deadline, move || {
                let plan = native
                    .plan_recovery(source)
                    .map_err(|e| error("cold exit recovery plan", e))?;
                native
                    .recover(plan, generation)
                    .map_err(|e| error("cold exit observation", e))
            })
            .await?;
        match outcome {
            se_proc::RecoveryOutcome::Exited(witness) => {
                work.native_already_reconciled = true;
                work.last_witness = Some((*witness).clone());
                if let Err(error) = self.finish(&mut work, *witness, deadline).await {
                    work.cleanup_failure = Some(error.body);
                }
            }
            se_proc::RecoveryOutcome::Recovered { process, record } => {
                // Contradicting a terminal record grants no new stop mutation.
                // Keep native custody for outside diagnosis, never signal it.
                work.process = Some(Arc::new(process));
                work.record = Some(*record);
                work.cleanup_failure=Some(error("cold exit contradiction","the exact original process is live despite its recorded exit; owner diagnosis is required").body);
            }
            se_proc::RecoveryOutcome::Unproved { error: reason, .. } => {
                work.cleanup_failure = Some(error("cold exit proof", format!("{reason:?}")).body)
            }
            _ => {
                work.cleanup_failure =
                    Some(error("cold exit proof", "no current outside exit witness").body)
            }
        }
        let complete = work.released;
        let job = self.retain_recovered(work)?;
        if complete {
            job.settled.store(true, Ordering::Release);
            self.activity
                .send_modify(|count| *count = count.saturating_sub(1));
        }
        Ok(Some(job))
    }
}
