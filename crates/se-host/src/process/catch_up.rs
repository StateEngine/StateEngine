//! The host's coalesced live-work sweep uses only retained indexed lifecycles.
use super::*;
use crate::client::lease::Deadline;
use std::sync::atomic::Ordering;
impl LaunchCoordinator {
    pub(super) async fn catch_up_live(&self, deadline: &Deadline) -> Result<()> {
        let jobs: Vec<_> = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("live-work catch-up", "launch registry is poisoned"))?
            .values()
            .filter(|job| !job.settled.load(Ordering::Acquire))
            .cloned()
            .collect();
        let capture = self.capture.in_background();
        let mut first_failure = None;
        for job in jobs {
            deadline.remaining()?;
            let mut work = crate::runtime::pool::within(deadline, job.state.lock()).await?;
            let observed = self.exit_observation(&work, deadline).await;
            match observed {
                Ok(se_proc::StopObservation::Complete(witness)) => {
                    work.admission = work.cleanup_admission.clone();
                    match self.finish(&mut work, *witness, deadline).await {
                        Ok(()) => {
                            if !job.settled.swap(true, Ordering::AcqRel) {
                                self.activity
                                    .send_modify(|count| *count = count.saturating_sub(1));
                            }
                        }
                        Err(error) => {
                            work.cleanup_failure = Some(error.body.clone());
                            first_failure.get_or_insert(error);
                        }
                    }
                }
                Ok(_) => {
                    if let Err(error) = self
                        .capture_progress_using(&mut work, deadline, &capture)
                        .await
                    {
                        first_failure.get_or_insert(error);
                    }
                }
                Err(error) => {
                    work.cleanup_failure = Some(error.body.clone());
                    first_failure.get_or_insert(error);
                }
            }
            job.wake.event.notify_one();
        }
        match first_failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
