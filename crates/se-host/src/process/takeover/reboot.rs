//! Let launch join startup cleanup of a positively witnessed previous boot.
use super::*;

impl LaunchCoordinator {
    pub(super) async fn finish_rebooted_launch(
        &self,
        plan: &LaunchPlan,
        deadline: &Deadline,
    ) -> Result<bool> {
        let records = if plan.control.processes.is_empty() && !plan.control.sessions.is_empty() {
            match &plan.control.latest_process {
                se_types::Read::Present { value } => std::slice::from_ref(value),
                _ => &[],
            }
        } else {
            plan.control.processes.as_slice()
        };
        let mut closed = false;
        for record in records {
            let identity = process_identity(record)?;
            let Some(job) = self
                .find_lifecycle_job(&plan.project.id, &plan.agent.id, &identity.record)?
                .filter(|job| job.ended_by_reboot)
            else {
                continue;
            };
            let mut work = crate::runtime::pool::within(deadline, job.state.lock()).await?;
            let Some(witness) = work.last_witness.clone().filter(|w| w.ended_by_reboot()) else {
                continue;
            };
            if !work.released {
                work.admission = work.cleanup_admission.clone();
                self.finish(&mut work, witness, deadline).await?;
                if !job.settled.swap(true, Ordering::AcqRel) {
                    self.activity
                        .send_modify(|count| *count = count.saturating_sub(1));
                }
            }
            closed = true;
        }
        Ok(closed)
    }
}
