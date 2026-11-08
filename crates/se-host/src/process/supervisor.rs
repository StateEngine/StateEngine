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
    pub session: se_types::SessionId,
    pub lifecycle: se_types::LifecycleId,
    pub state: AsyncMutex<Work>,
    pub ready: watch::Sender<Option<std::result::Result<LaunchResult, ErrorBody>>>,
    pub settled: AtomicBool,
    pub mail_pending: AtomicBool,
    pub capture_pending: AtomicBool,
    pub wake: Arc<events::Wake>,
    pub task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub fault: Mutex<Option<String>>,
}
impl Job {
    /// Inspection and release do not interrupt startup. Leave time to return a
    /// named refusal instead of spending the caller's IPC clock on its lock.
    pub(super) async fn control_state(
        &self,
        deadline: &Deadline,
    ) -> Result<tokio::sync::MutexGuard<'_, Work>> {
        deadline.remaining()?;
        if let Ok(work) = self.state.try_lock() {
            return Ok(work);
        }
        let refused = || {
            let pending = self.wake.awaiting_window.load(Ordering::Acquire);
            SeError::new(se_types::Detail::LaunchFailed(
                se_types::details::LaunchFailed {
                    subject: "agent control".into(),
                    reason: if pending {
                        "This agent is still completing setup in its welcome or workspace trust window. No replacement or release was performed."
                    } else {
                        "This agent is busy finishing its launch or another control request. No replacement or release was performed."
                    }.into(),
                    next_step: if pending {
                        "Finish setup in the existing window, or stop this agent explicitly to cancel the pending launch before retrying."
                    } else {
                        "Retry after the current operation finishes; stop this agent explicitly to cancel a pending launch."
                    }.into(),
                },
            ))
        };
        if self.wake.awaiting_window.load(Ordering::Acquire) {
            return Err(refused());
        }
        let bound = deadline.stage(std::time::Duration::from_secs(1))?;
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(bound.at()),
            self.state.lock(),
        )
        .await
        .map_err(|_| refused())
    }
}
impl LaunchCoordinator {
    /// Includes prepared launches and unresolved cleanup, not just providers
    /// currently running. The host's one empty-host timer may arm only at zero.
    pub fn subscribe_activity(&self) -> watch::Receiver<u32> {
        self.activity.subscribe()
    }
    pub(super) async fn launch_prepared(
        self: &Arc<Self>,
        plan: LaunchPlan,
        admission: Admission,
        deadline: &Deadline,
        takeover: Option<se_core::ops::agent_launch::TakeoverReport>,
    ) -> Result<LaunchResult> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(se_core::scope::unreadable(
                "launch admission",
                "the host is joining its owned processes; reconnect after shutdown completes",
            ));
        }
        // Readiness leaves six seconds for retained cleanup and two for its
        // response, rather than spending the caller's whole clock first.
        let retained_deadline = deadline.retained().stage(
            deadline
                .remaining()?
                .saturating_sub(std::time::Duration::from_secs(8)),
        )?;
        let attended = !plan.input.detach && plan.profile.provider == se_store::Provider::Claude;
        let waiter = if attended {
            // The CLI's call budget also covers cold host startup. Return a
            // useful pending result before that client clock expires; this
            // does not shorten native custody or the human onboarding wait.
            deadline.stage(
                deadline
                    .remaining()?
                    .saturating_sub(std::time::Duration::from_secs(2))
                    .min(std::time::Duration::from_secs(15)),
            )?
        } else {
            deadline.clone()
        };
        let key = format!(
            "{:?}/{:?}/{}",
            admission.scope, admission.actor, plan.input.idempotency_key
        );
        let intent = Sha256::digest(
            serde_json::to_vec(&plan.input.intent(&plan.agent.id)?)
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
                let mut work = Work::new(plan, admission);
                work.takeover = takeover;
                let wake = work.wake.clone();
                let job = Arc::new(Job {
                    intent,
                    target,
                    session: work.meta.session.clone(),
                    lifecycle,
                    state: AsyncMutex::new(work),
                    ready: watch::channel(None).0,
                    settled: AtomicBool::new(false),
                    mail_pending: AtomicBool::new(true),
                    capture_pending: AtomicBool::new(false),
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
                        match coordinator.retain_expired_window(&mut state).await {
                            Ok(true) => {
                                owned.ready.send_replace(Some(Err(coordinator.expired_window_error(&state).body)));
                                drop(state);
                                coordinator.monitor_protected(owned.clone()).await;
                                return;
                            }
                            Ok(false) => (),
                            Err(failure) => {
                                state.cleanup_failure = Some(failure.body);
                            }
                        }
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
                    if let Ok(mut fault) = owned.fault.lock() { *fault = Some("session supervisor panicked; explicit reconciliation required".into()); }
                    owned.ready.send_replace(Some(Err(failure.body)));
                }
            });
            *job.task
                .lock()
                .map_err(|_| SeError::invalid("launch task", "unpoisoned retained task slot"))? =
                Some(task);
        }
        let waiting_since = std::time::Instant::now();
        let mut ready = job.ready.subscribe();
        loop {
            if let Some(result) = ready.borrow().clone() {
                return result.map_err(|body| SeError { body, cause: None });
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(waiter.at()),
                ready.changed(),
            )
            .await
            .map_err(|_| {
                if attended {
                    let last_observed = if job.wake.awaiting_window.load(Ordering::Acquire) {
                        "Complete Claude's welcome or workspace trust prompt in its window. StateEngine keeps waiting while that same process is alive."
                    } else {
                        "The window launch is still in progress under native supervision; inspect this agent's status."
                    };
                    return SeError::new(se_types::Detail::LaunchReadinessTimeout(se_types::details::LaunchReadinessTimeout {
                        agent: job.target.1.clone(), waited_ms: waiting_since.elapsed().as_millis() as u64, last_observed: last_observed.into(),
                    }));
                }
                se_core::scope::unreadable(
                    "launch request wait",
                    "the supervisor retains the original request; retry with the same key",
                )
            })?
            .map_err(|e| error("launch supervisor result", e))?;
        }
    }
}
