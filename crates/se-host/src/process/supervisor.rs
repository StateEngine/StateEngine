//! Bounded retained jobs keyed by the admitted original request. A cancelled
//! connection drops only its waiter; the job keeps process and commit custody.
use super::launch::Work;
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{
    LaunchPending, LaunchPendingState, LaunchReply, LaunchResult, agent_launch::LaunchPlan,
};
use se_core::scope::unreadable;
use se_store::Admission;
use se_types::{ErrorBody, Result, SeError};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, watch},
    time::{Instant, timeout_at},
};

#[derive(Clone, Debug)]
pub(super) struct CodexBinding {
    /// Raw login path used to key the durable server record.
    pub raw_login: PathBuf,
    /// Canonical physical login directory when proved at launch/recovery.
    pub canonical_login: Option<PathBuf>,
    /// Exact OS process identity of the shared Codex server bound to this job, when known.
    pub server: Option<se_proc::ProcessIdentity>,
}

#[derive(Default)]
pub(super) struct Jobs(pub Mutex<BTreeMap<String, Arc<Job>>>);
pub(super) struct Job {
    pub(super) intent: [u8; 32],
    pub target: (se_types::ProjectId, se_types::AgentId),
    pub session: se_types::SessionId,
    pub lifecycle: se_types::LifecycleId,
    /// Fixed for the lifecycle; lets a login's shared server count its agents.
    pub provider: se_store::Provider,
    /// Login and shared-server binding for this Codex job (for per-server accounting).
    pub codex_login: Mutex<Option<CodexBinding>>,
    pub ended_by_reboot: bool,
    /// Immutable metadata shared with Work; pending replies never wait on its lock.
    pub plan: Option<Arc<LaunchPlan>>,
    pub takeover: Option<se_core::ops::agent_launch::TakeoverReport>,
    pub state: AsyncMutex<Work>,
    pub ready: watch::Sender<Option<std::result::Result<LaunchResult, ErrorBody>>>,
    pub settled: AtomicBool,
    pub mail_pending: AtomicBool,
    pub mail_reoffer: AtomicBool,
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
        let bound = deadline.stage(Duration::from_secs(1))?;
        timeout_at(Instant::from_std(bound.at()), self.state.lock())
            .await
            .map_err(|_| refused())
    }
}
struct AdmittedJob {
    job: Arc<Job>,
    created: bool,
}

fn ready_reply(
    ready: &watch::Receiver<Option<std::result::Result<LaunchResult, ErrorBody>>>,
) -> Option<Result<LaunchReply>> {
    ready.borrow().clone().map(|result| {
        result
            .map(LaunchReply::from)
            .map_err(|body| SeError { body, cause: None })
    })
}

impl LaunchCoordinator {
    /// Includes prepared launches and unresolved cleanup, not just providers
    /// currently running. The host's one empty-host timer may arm only at zero.
    pub fn subscribe_activity(&self) -> watch::Receiver<u32> {
        self.activity.subscribe()
    }
    fn admit_job(
        &self,
        plan: LaunchPlan,
        admission: Admission,
        takeover: Option<se_core::ops::agent_launch::TakeoverReport>,
        #[cfg(feature = "remote")] permit: Option<crate::remote::auth::AdmissionPermit>,
    ) -> Result<AdmittedJob> {
        let key = format!(
            "{:?}/{:?}/{}",
            admission.scope, admission.actor, plan.input.idempotency_key
        );
        let intent = Sha256::digest(
            serde_json::to_vec(&plan.input.intent(&plan.agent.id)?)
                .map_err(|e| error("launch intent", e))?,
        )
        .into();
        let mut jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| SeError::invalid("launch supervisors", "unpoisoned registry"))?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(unreadable(
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
            return Ok(AdmittedJob {
                job: job.clone(),
                created: false,
            });
        }
        let target = (plan.project.id.clone(), plan.agent.id.clone());
        if jobs
            .values()
            .any(|job| job.target == target && !job.settled.load(Ordering::Acquire))
        {
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
        let lifecycle = plan.lifecycle.clone();
        let plan = Arc::new(plan);
        let mut work = Work::new(plan.clone(), admission);
        work.takeover = takeover.clone();
        #[cfg(feature = "remote")]
        {
            work.remote_permit = permit;
        }
        let wake = work.wake.clone();
        let job = Arc::new(Job {
            ended_by_reboot: false,
            intent,
            target,
            session: work.meta.session.clone(),
            lifecycle,
            provider: work.meta.provider,
            codex_login: Mutex::new(None),
            plan: Some(plan),
            takeover,
            state: AsyncMutex::new(work),
            ready: watch::channel(None).0,
            settled: AtomicBool::new(false),
            mail_pending: AtomicBool::new(true),
            mail_reoffer: AtomicBool::new(false),
            capture_pending: AtomicBool::new(false),
            wake,
            task: Mutex::new(None),
            fault: Mutex::new(None),
        });
        jobs.insert(key, job.clone());
        self.inc_activity();
        Ok(AdmittedJob { job, created: true })
    }
    fn spawn_launch_task(
        self: &Arc<Self>,
        job: &Arc<Job>,
        retained_deadline: Deadline,
        launch_guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<()> {
        let (coordinator, owned) = (self.clone(), job.clone());
        let sign_in = crate::launch_sign_in::current(); // `None` for a host restore.
        let task = self.store.pool.handle().spawn(async move {
            let completed = crate::runtime::tasks::caught(async {
                let deadline = retained_deadline;
                let mut state = owned.state.lock().await;
                let mut launch_guard = Some(launch_guard);
                let start = crate::launch_sign_in::scope(
                    sign_in,
                    coordinator.start(&mut state, &mut launch_guard, &deadline),
                );
                let started = crate::runtime::tasks::caught(start, false).await
                    .unwrap_or_else(|()| Err(error("launch session task", "panicked with its original key and partial custody retained; reconcile before retry")));
                // Drop any still-held pre-C1 launch guard unconditionally on
                // every failure or panic path before cleanup/caching.
                drop(launch_guard);
                let mut timing = state.startup_timing.take();
                match started {
                    Ok(output) => {
                        owned.ready.send_replace(Some(Ok(output)));
                        drop(state);
                        coordinator.monitor_protected(owned.clone()).await;
                    }
                    Err(original) => {
                        if let Some(timing) = &mut timing {
                            timing.freeze();
                        }
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
                            Ok(()) => { owned.settled.store(true, Ordering::Release); coordinator.dec_activity(); original.body }
                            Err(cleanup) => {
                                state.cleanup_failure = Some(cleanup.body.clone());
                                if matches!(original.body.detail(), se_types::Detail::LaunchFailed(_)) {
                                    super::readiness::refused(&owned.target.1, "provider readiness with retained cleanup", format!("launch={original}; cleanup remains unproved: {cleanup}")).body
                                } else {
                                    se_core::scope::unreadable("launch failed with retained cleanup", &format!("launch={original}; cleanup={cleanup}; retry the original request identity to inspect its retained custody")).body
                                }
                            }
                        };
                        let failure = match timing {
                            Some(timing) => timing.report(failure, &owned.target.1),
                            None => failure,
                        };
                        owned.ready.send_replace(Some(Err(failure)));
                        if !owned.settled.load(Ordering::Acquire) {
                            drop(state);
                            coordinator.monitor_protected(owned.clone()).await;
                        }
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
        Ok(())
    }
    pub(super) async fn launch_prepared(
        self: &Arc<Self>,
        plan: LaunchPlan,
        admission: Admission,
        deadline: &Deadline,
        takeover: Option<se_core::ops::agent_launch::TakeoverReport>,
        launch_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
        #[cfg(feature = "remote")] permit: Option<crate::remote::auth::AdmissionPermit>,
    ) -> Result<LaunchReply> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(unreadable(
                "launch admission",
                "the host is joining its owned processes; reconnect after shutdown completes",
            ));
        }
        // Readiness leaves six seconds for retained cleanup and two for its
        // response, rather than spending the caller's whole clock first.
        let retained_deadline = deadline
            .retained()
            .stage(deadline.remaining()?.saturating_sub(Duration::from_secs(8)))?;
        let attended = !plan.input.detach && plan.profile.provider == se_store::Provider::Claude;
        let waiter = if attended {
            // The CLI's call budget also covers cold host startup. Return a
            // useful pending result before that client clock expires; this
            // does not shorten native custody or the human onboarding wait.
            deadline.stage(
                deadline
                    .remaining()?
                    .saturating_sub(Duration::from_secs(2))
                    .min(Duration::from_secs(15)),
            )?
        } else {
            deadline.clone()
        };
        // Serialize job-slot admission with any active takeover for this agent
        // through C1 reservation; the guard drops immediately after C1 (or on
        // any pre-C1 error/panic) inside the retained launch task.
        let launch_guard = match launch_guard {
            Some(guard) => guard,
            None => {
                self.lock_agent_launch(&plan.project.id, &plan.agent.id, deadline)
                    .await?
            }
        };
        let admitted = self.admit_job(
            plan,
            admission,
            takeover,
            #[cfg(feature = "remote")]
            permit,
        )?;
        if admitted.created {
            self.spawn_launch_task(&admitted.job, retained_deadline, launch_guard)?;
        } else {
            drop(launch_guard);
        }
        let job = &admitted.job;
        let mut ready = job.ready.subscribe();
        loop {
            if let Some(reply) = ready_reply(&ready) {
                return reply;
            }
            match timeout_at(Instant::from_std(waiter.at()), ready.changed()).await {
                Ok(changed) => changed.map_err(|e| error("launch supervisor result", e))?,
                Err(_) if attended => {
                    // Completion can race the waiter; never hide an already known failure.
                    if let Some(reply) = ready_reply(&ready) {
                        return reply;
                    }
                    deadline.remaining()?;
                    job.wake.require_startup()?;
                    let state = if job.wake.awaiting_window.load(Ordering::Acquire) {
                        LaunchPendingState::SetupNeeded
                    } else {
                        LaunchPendingState::Starting
                    };
                    let plan = job.plan.as_deref().ok_or_else(|| {
                        error(
                            "launch pending metadata",
                            "the original launch plan is unavailable; inspect the retained lifecycle",
                        )
                    })?;
                    return Ok(LaunchReply::Pending(Box::new(LaunchPending::new(
                        plan,
                        state,
                        &self.options.home,
                        job.takeover.clone(),
                    ))));
                }
                Err(_) => {
                    return Err(unreadable(
                        "launch request wait",
                        "the supervisor retains the original request; retry with the same key",
                    ));
                }
            }
        }
    }
}
