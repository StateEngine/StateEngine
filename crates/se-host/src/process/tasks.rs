//! Session monitor restarts reuse the same retained Work, keys and cursors.
use super::*;
use std::sync::atomic::Ordering;
impl LaunchCoordinator {
    pub(super) fn task_status(
        &self,
        output: &mut se_core::ops::AnyOutput,
        scope: &se_store::Scope,
        actor: &se_store::Actor,
    ) -> Result<()> {
        let se_core::ops::AnyOutput::ProjectStatus(status) = output else {
            return Ok(());
        };
        for name in self.store.fault.failed_routes()? {
            status.value.pending.push(se_core::ops::PendingFact { what: name.into(), since: None, detail: "This listener route failed; retry is bounded to once per minute while other routes and native sessions remain available.".into() });
        }
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("session task status", "retained registry is poisoned"))?;
        for job in jobs.values() {
            if job.settled.load(Ordering::Acquire)
                || !matches!(scope, se_store::Scope::Project(project) if *project == job.target.0)
                || matches!(actor, se_store::Actor::Agent(agent) if *agent != job.target.1)
            {
                continue;
            }
            let fault = job
                .fault
                .lock()
                .map_err(|_| error("session task status", "fault diagnostic is poisoned"))?;
            if let Some(reason) = fault.as_ref() {
                status.value.pending.push(se_core::ops::PendingFact {
                    what: format!("session task {}", job.lifecycle),
                    since: None,
                    detail: reason.clone(),
                });
            }
        }
        Ok(())
    }
    pub(super) async fn monitor_protected(self: &Arc<Self>, job: Arc<supervisor::Job>) {
        let mut budget = crate::runtime::tasks::FaultBudget::default();
        loop {
            if crate::runtime::tasks::caught(self.monitor(job.clone()), false)
                .await
                .is_ok()
            {
                if job.settled.load(Ordering::Acquire)
                    && let Ok(mut fault) = job.fault.lock()
                {
                    *fault = None;
                }
                return;
            }
            let now = std::time::Instant::now();
            let restart = budget.available(now);
            budget.failed(now);
            if let Ok(mut fault) = job.fault.lock() {
                *fault = Some(if restart {
                    "session monitor recovering original keys and cursors"
                } else {
                    "session monitor exhausted three restarts in 60 seconds; explicit reconciliation required"
                }.into());
            }
            let failure = error(
                "session monitor",
                format!(
                    "lifecycle {} panicked; {}",
                    job.lifecycle,
                    if restart {
                        "recovering its retained original keys and cursors"
                    } else {
                        "three restarts in 60 seconds exhausted; explicit stop or reconciliation is required"
                    }
                ),
            );
            let mut state = job.state.lock().await;
            state.cleanup_failure = Some(failure.body.clone());
            if let Err(error) = self.report_capture_failure(&state, &failure).await {
                state.cleanup_failure = Some(error.body);
            }
            drop(state);
            if !restart || job.settled.load(Ordering::Acquire) {
                return;
            }
            // monitor begins with an actual native read, never another launch.
            tokio::task::yield_now().await;
        }
    }
}
