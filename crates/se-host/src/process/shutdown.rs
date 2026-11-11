//! Join retained lifecycle jobs before the host fences capture and drains its
//! writer. A timeout retains both the task and native ownership for retry.
use super::supervisor::Job;
use super::*;
use crate::client::lease::Deadline;
use se_types::Result;
use std::sync::atomic::Ordering;
#[derive(Default)]
pub struct ProcessDrain {
    pub complete: bool,
    pub stopped: u32,
    pub pending: Vec<String>,
}
impl LaunchCoordinator {
    /// Called after listener admission stops, before the capture fence or
    /// storage drain. It never aborts a task that could still own a native child.
    pub async fn shutdown(&self, deadline: &Deadline) -> Result<ProcessDrain> {
        self.stopping.store(true, Ordering::Release);
        let mut report = ProcessDrain::default();
        self.join_controls(deadline, &mut report.pending).await?;
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("process shutdown", "poisoned job registry"))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        // Poll every retained lifecycle together: one provider's graceful wait
        // must not spend every later provider's share of the same deadline.
        // These borrowed futures are joined here, never detached or aborted.
        let mut stopping = jobs
            .iter()
            .map(|job| async {
                self.shutdown_job(job, deadline).await.map_err(|error| {
                    format!(
                        "agent {} lifecycle {}: {error}",
                        job.target.1, job.lifecycle
                    )
                })
            })
            .collect::<futures_util::stream::FuturesUnordered<_>>();
        use futures_util::StreamExt;
        while let Some(result) = stopping.next().await {
            match result {
                Ok(part) => {
                    report.stopped = report.stopped.saturating_add(part.stopped);
                    report.pending.extend(part.pending);
                }
                Err(reason) => report.pending.push(reason),
            }
        }
        report.pending.extend(self.shutdown_secode(deadline).await?);
        report
            .pending
            .extend(self.shutdown_observed(deadline).await?);
        let native = self.native.clone();
        match self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .arena_snapshot()
                    .map_err(|e| error("shutdown native inventory", e))
            })
            .await
        {
            Ok(snapshot) => {
                if !snapshot.complete {
                    report
                        .pending
                        .push("Native ownership inventory is incomplete".into());
                }
                for entry in snapshot.entries {
                    report.pending.push(format!(
                        "{}: native arena custody remains in {:?}",
                        entry.reservation.lifecycle, entry.phase
                    ));
                }
            }
            Err(error) => report
                .pending
                .push(format!("Native ownership could not be read: {error}")),
        }
        let outstanding = *self.activity.borrow();
        if outstanding != 0 {
            report.pending.push(format!(
                "{outstanding} native or cleanup obligations remain retained"
            ));
        }
        report.complete = report.pending.is_empty();
        Ok(report)
    }
    async fn shutdown_job(&self, job: &Arc<Job>, deadline: &Deadline) -> Result<ProcessDrain> {
        let mut report = ProcessDrain::default();
        let lifecycle = format!(
            "agent {} project {} lifecycle {}",
            job.target.1, job.target.0, job.lifecycle
        );
        if !job.settled.load(Ordering::Acquire) {
            self.interrupt_startup(
                job,
                &format!("shutdown-startup-{}", job.lifecycle).parse()?,
                se_store::Admission {
                    actor: se_store::Actor::Human(self.human.clone()),
                    scope: se_store::Scope::Project(job.target.0.clone()),
                    session: None,
                    generation: self.store.generation.get(),
                },
                deadline,
            )
            .await?;
            let result = async {
                let mut work = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline.at()),
                    job.state.lock(),
                )
                .await
                .map_err(|_| {
                    error(
                        "process shutdown",
                        "the original launch still owns its lifecycle lock",
                    )
                })?;
                if !work.released {
                    work.admission = work.cleanup_admission.clone();
                    if !work.active {
                        self.cleanup_failed(&mut work, deadline).await?;
                    } else {
                        let witness = self.stop_native(&mut work, deadline).await?;
                        self.finish(&mut work, witness, deadline).await?;
                    }
                }
                work.wake.event.notify_waiters();
                work.wake.event.notify_one();
                Ok::<(), se_types::SeError>(())
            }
            .await;
            match result {
                Ok(()) => {
                    if !job.settled.swap(true, Ordering::AcqRel) {
                        self.activity
                            .send_modify(|count| *count = count.saturating_sub(1));
                    }
                    report.stopped = report.stopped.saturating_add(1);
                }
                Err(error) => {
                    report.pending.push(format!("{lifecycle}: {error}"));
                    return Ok(report);
                }
            }
        }
        let task = job
            .task
            .lock()
            .map_err(|_| error("process shutdown", "poisoned task slot"))?
            .take();
        if let Some(mut task) = task {
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()), &mut task)
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => report
                    .pending
                    .push(format!("{lifecycle}: monitor join failed: {error}")),
                Err(_) => {
                    *job.task
                        .lock()
                        .map_err(|_| error("process shutdown", "poisoned task slot"))? = Some(task);
                    report
                        .pending
                        .push(format!("{lifecycle}: monitor join remains owned"));
                }
            }
        }
        Ok(report)
    }
}
