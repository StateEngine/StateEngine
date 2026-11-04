//! Bounded retained jobs keyed by the admitted original request. A cancelled
//! connection drops only its waiter; the job keeps process and commit custody.
use super::launch::Work;
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{LaunchResult, agent_launch::LaunchPlan};
use se_store::Admission;
use se_types::{ErrorBody, Result, SeError};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex as AsyncMutex, watch};

#[derive(Default)]
pub(super) struct Jobs(pub Mutex<BTreeMap<String, Arc<Job>>>);
pub(super) struct Job {
    pub(super) intent: [u8; 32],
    pub target: (se_types::ProjectId, se_types::AgentId),
    pub lifecycle: se_types::LifecycleId,
    pub state: AsyncMutex<Work>,
    pub ready: watch::Sender<Option<std::result::Result<LaunchResult, ErrorBody>>>,
    pub settled: AtomicBool,
    pub mail_pending: AtomicBool,
    pub wake: Arc<events::Wake>,
    pub task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub fault: Mutex<Option<&'static str>>,
}
impl LaunchCoordinator {
    /// Includes prepared launches and unresolved cleanup, not just providers
    /// currently running. The host's one empty-host timer may arm only at zero.
    pub fn subscribe_activity(&self) -> watch::Receiver<u32> {
        self.activity.subscribe()
    }
    pub async fn launch(
        self: &Arc<Self>,
        plan: LaunchPlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<LaunchResult> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(se_core::scope::unreadable(
                "launch admission",
                "the host is joining its owned processes; reconnect after shutdown completes",
            ));
        }
        let key = format!(
            "{:?}/{:?}/{}",
            admission.scope, admission.actor, plan.input.idempotency_key
        );
        let intent = Sha256::digest(
            serde_json::to_vec(&serde_json::json!({"input":plan.input,"agent":plan.agent.id}))
                .map_err(|e| error("launch intent", e))?,
        )
        .into();
        let (job, new) = {
            let mut jobs = self
                .jobs
                .0
                .lock()
                .map_err(|_| SeError::invalid("launch supervisors", "unpoisoned registry"))?;
            if self.stopping.load(Ordering::Acquire) {
                return Err(se_core::scope::unreadable(
                    "launch admission",
                    "shutdown began before lifecycle reservation",
                ));
            }
            if let Some(job) = jobs.get(&key) {
                if job.intent != intent {
                    return Err(SeError::invalid(
                        "launch request key",
                        "the original arguments and target",
                    ));
                }
                (job.clone(), false)
            } else {
                if jobs.values().any(|job| {
                    job.target == (plan.project.id.clone(), plan.agent.id.clone())
                        && !job.settled.load(Ordering::Acquire)
                }) {
                    return Err(SeError::invalid(
                        "launch target",
                        "stop or finish the existing launch before starting a different request",
                    ));
                }
                // Keep only a bounded result cache. Retained store receipts
                // remain authoritative after eviction; no duplicate C1 spawns.
                let bound = (self.options.maximum_sessions as usize)
                    .saturating_mul(4)
                    .max(16);
                if jobs.len() >= bound
                    && let Some(old) = jobs
                        .iter()
                        .find(|(_, j)| j.settled.load(Ordering::Acquire))
                        .map(|(k, _)| k.clone())
                {
                    jobs.remove(&old);
                }
                if jobs.len() >= bound {
                    return Err(SeError::invalid(
                        "launch capacity",
                        "resolve retained active/cleanup jobs before launching more agents",
                    ));
                }
                let target = (plan.project.id.clone(), plan.agent.id.clone());
                let lifecycle = plan.lifecycle.clone();
                let work = Work::new(plan, admission);
                let wake = work.wake.clone();
                let job = Arc::new(Job {
                    intent,
                    target,
                    lifecycle,
                    state: AsyncMutex::new(work),
                    ready: watch::channel(None).0,
                    settled: AtomicBool::new(false),
                    mail_pending: AtomicBool::new(true),
                    wake,
                    task: Mutex::new(None),
                    fault: Mutex::new(None),
                });
                jobs.insert(key, job.clone());
                self.activity
                    .send_modify(|count| *count = count.saturating_add(1));
                (job, true)
            }
        };
        if new {
            let retained_deadline = deadline.retained();
            let coordinator = self.clone();
            let owned = job.clone();
            let task = self.store.pool.handle().spawn(async move {
                let completed = crate::runtime::tasks::caught(async {
                let deadline = retained_deadline;
                let mut state = owned.state.lock().await;
                let started = crate::runtime::tasks::caught(coordinator.start(&mut state, &deadline), false).await
                    .unwrap_or_else(|()| Err(error("launch session task", "panicked with its original key and partial custody retained; reconcile before retry")));
                match started {
                    Ok(output) => {
                        owned.ready.send_replace(Some(Ok(output)));
                        drop(state);
                        coordinator.monitor_protected(owned.clone()).await;
                    }
                    Err(original) => {
                        let cleanup = Deadline::idle().and_then(|value| value.stage(std::time::Duration::from_secs(6)));
                        let result = match cleanup { Ok(cleanup) => coordinator.cleanup_failed(&mut state, &cleanup).await, Err(error) => Err(error) };
                        let failure = match result {
                            Ok(()) => { owned.settled.store(true,Ordering::Release); coordinator.activity.send_modify(|count| *count=count.saturating_sub(1)); original.body }
                            Err(cleanup) => {
                                state.cleanup_failure = Some(cleanup.body.clone());
                                se_core::scope::unreadable("launch failed with retained cleanup", &format!("launch={original}; cleanup={cleanup}; retry the original request identity to inspect its retained custody")).body
                            }
                        };
                        owned.ready.send_replace(Some(Err(failure)));
                    }
                }
                }, false).await;
                if completed.is_err() {
                    let failure = error("session supervisor", "panicked; original lifecycle custody remains retained for explicit stop or reconciliation");
                    if let Ok(mut fault) = owned.fault.lock() { *fault = Some("session supervisor panicked; explicit reconciliation required"); }
                    owned.ready.send_replace(Some(Err(failure.body)));
                }
            });
            *job.task
                .lock()
                .map_err(|_| SeError::invalid("launch task", "unpoisoned retained task slot"))? =
                Some(task);
        }
        let mut ready = job.ready.subscribe();
        loop {
            if let Some(result) = ready.borrow().clone() {
                return result.map_err(|body| SeError { body, cause: None });
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline.at()),
                ready.changed(),
            )
            .await
            .map_err(|_| {
                se_core::scope::unreadable(
                    "launch request wait",
                    "the supervisor retains the original request; retry with the same key",
                )
            })?
            .map_err(|e| error("launch supervisor result", e))?;
        }
    }
}
