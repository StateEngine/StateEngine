//! Host-owned composite `delegate.start`, `delegate.cancel`, one-shot turn-1
//! auto-stop, and atomic post-`SessionEnded` completion notice + retirement.
use super::{supervisor::Job, *};
use crate::client::lease::Deadline;
use se_core::{
    ops::{
        AgentLaunch, LaunchReply,
        delegate::{
            CompletionNoticeInput, DelegateCancelOutput, DelegateCancelPlan, DelegateStartOutput,
            DelegateStartPlan, completion_notice_batch, create_ephemeral_batch,
        },
        process_commit, process_plan,
    },
    store_error::store_error,
};
use se_store::{Admission, EventBody, RetirementReason, Snapshot};
use se_types::{Named, Read, Result};
use std::{sync::atomic::Ordering, time::Duration};

pub(super) struct OneShotCompletion {
    pub project: se_types::ProjectId,
    pub agent: Named<se_types::AgentId>,
    pub owner: se_types::HumanId,
    pub child_session: se_types::SessionId,
    pub provider: Option<se_store::Provider>,
    pub model: Option<String>,
    pub outcome: String,
    pub capture: se_core::ops::delegate::CaptureOutcome,
    pub reason: RetirementReason,
}

impl LaunchCoordinator {
    /// Qualify provider/harness BEFORE creating the ephemeral principal so a
    /// failed qualification never leaves an orphan agent behind (`I12`).
    pub(super) async fn delegate_start(
        self: &Arc<Self>,
        plan: DelegateStartPlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<DelegateStartOutput> {
        let newly_created = plan.existing_agent.is_none();
        let (agent_id, name) = if let Some(existing) = &plan.existing_agent {
            existing.clone()
        } else {
            self.qualify_delegate(&plan, deadline).await?;
            let commit_plan = plan.clone();
            {
                let _create_guard =
                    crate::runtime::pool::within(deadline, self.delegate_create_lock.lock())
                        .await?;
                self.store
                    .commit(admission.clone(), deadline, None, move |kernel, cx| {
                        create_ephemeral_batch(kernel, &commit_plan, cx)
                    })
                    .await?;
            }
            let wait = Duration::from_secs(u64::from(plan.ephemeral.ttl_seconds))
                .saturating_add(Duration::from_millis(100));
            self.arm_ephemeral_ttl(wait);
            (plan.agent_id.clone(), plan.name.clone())
        };
        let launch_key = process_commit::phase_key(&plan.idempotency_key, "delegate-launch")?;
        let launch_input = AgentLaunch {
            target_agent_id: Some(agent_id.clone()),
            resume: None,
            model: plan.model.clone(),
            task: Some(plan.composed_task.clone()),
            detach: true,
            override_live: false,
            force_selection: None,
            idempotency_key: launch_key,
            owner_agent: None,
            owner_provider: None,
        };
        let configuration = self.options.configuration.clone();
        let launch_plan = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                let facts = crate::runtime::start::allocate_facts()?;
                let kernel = se_core::dispatch::Kernel::new(facts)?;
                process_plan::launch(&kernel, launch_input, &configuration, cx)
            })
            .await;
        let reply = match launch_plan {
            Ok(lp) => self.launch(lp, admission.clone(), deadline).await,
            Err(err) => Err(err),
        };
        let reply = match reply {
            Ok(reply) => reply,
            Err(launch_err) => {
                if newly_created
                    && let Err(cleanup_err) = self
                        .retire_failed_delegate(&plan.project.id, &agent_id, &admission, deadline)
                        .await
                {
                    return Err(error(
                        "delegate.start",
                        format!(
                            "launch failed ({}); cleanup of temporary agent {agent_id} also failed ({}) and it remains active until TTL",
                            launch_err.body, cleanup_err.body
                        ),
                    ));
                }
                return Err(launch_err);
            }
        };
        let session_id = match reply {
            LaunchReply::Running(launched) => launched.session_id,
            LaunchReply::Pending(pending) => pending.session_id,
        };
        Ok(DelegateStartOutput {
            agent_id,
            name,
            session_id,
            provider: plan.provider,
            model: plan.model,
            profile: plan.named_profile,
            ttl_seconds: plan.ephemeral.ttl_seconds,
            handoff_included: plan.handoff_included,
        })
    }

    async fn qualify_delegate(&self, plan: &DelegateStartPlan, deadline: &Deadline) -> Result<()> {
        let harness = self.harness_for(plan.stored_provider)?;
        let provider = plan.provider;
        let configuration = self.options.configuration.clone();
        let configuration_file = self.configuration_file.clone();
        let harness_name = plan.harness.clone();
        let (command, qualification) = self
            .store
            .pool
            .run_owned(deadline, move || {
                let command = super::launch_util::resolve_provider_launch(
                    &configuration,
                    provider,
                    configuration_file.as_deref(),
                    harness_name.as_deref(),
                )?;
                let qualification = if provider == se_types::Provider::Codex {
                    se_proc::native_ipc::ExecutableStamp::observe(&command.executable)
                        .map_err(|e| error("Codex qualification image", e))?
                } else {
                    None
                };
                Ok((command, qualification))
            })
            .await?;
        harness
            .probe_direct(
                crate::ProbeRequest {
                    kind: harness.kind(),
                    command: command.executable,
                },
                qualification,
                super::launch_util::call(self.store.generation, deadline)?,
            )
            .await?;
        Ok(())
    }

    /// Clean up a freshly created ephemeral agent if `self.launch` fails before
    /// activation, so failed launches never leave counted orphans until TTL.
    /// Surfaces any cleanup failure instead of discarding it silently.
    async fn retire_failed_delegate(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        let bound = deadline.stage(Duration::from_secs(5))?;
        self.stop_ephemeral_jobs(project, agent, None, owned::OneShotExit::Cancelled, &bound)
            .await?;
        if self
            .has_unresolved_live_work(project, agent, &bound)
            .await?
        {
            return Err(error(
                "delegate.start cleanup",
                format!("temporary agent {agent} still has unresolved live work"),
            ));
        }
        let target = agent.clone();
        self.store
            .commit(admission.clone(), &bound, None, move |kernel, cx| {
                process_commit::retire_agent(kernel, target, RetirementReason::Cancelled, None, cx)
            })
            .await?;
        Ok(())
    }

    /// Stop any active lifecycle for a temporary agent and terminally retire it
    /// with `RetirementReason::Cancelled`.
    pub(super) async fn delegate_cancel(
        &self,
        plan: DelegateCancelPlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<DelegateCancelOutput> {
        let stopped_lifecycle = self
            .stop_ephemeral_jobs(
                &plan.project,
                &plan.agent.id,
                None,
                owned::OneShotExit::Cancelled,
                deadline,
            )
            .await?;
        if !plan.already_retired {
            if self
                .has_unresolved_live_work(&plan.project, &plan.agent.id, deadline)
                .await?
            {
                return Err(error(
                    "delegate.cancel",
                    format!(
                        "temporary agent {} still has live or unresolved sessions/processes; leaving unretired",
                        plan.agent.id
                    ),
                ));
            }
            let agent = plan.agent.id.clone();
            let final_session = plan.final_session.clone();
            let retired = self
                .store
                .read(admission.clone(), deadline, move |cx| {
                    cx.read
                        .principal_retired(agent)
                        .map_err(|e| store_error(&e))
                })
                .await?;
            if !retired {
                let agent = plan.agent.id.clone();
                if let Err(commit_err) = self
                    .store
                    .commit(admission.clone(), deadline, None, move |kernel, cx| {
                        process_commit::retire_agent(
                            kernel,
                            agent,
                            RetirementReason::Cancelled,
                            final_session,
                            cx,
                        )
                    })
                    .await
                {
                    let recheck = plan.agent.id.clone();
                    let now_retired = self
                        .store
                        .read(admission, deadline, move |cx| {
                            cx.read
                                .principal_retired(recheck)
                                .map_err(|e| store_error(&e))
                        })
                        .await
                        .unwrap_or(false);
                    if !now_retired {
                        return Err(commit_err);
                    }
                }
            }
        }
        Ok(DelegateCancelOutput {
            agent_id: plan.agent.id,
            name: plan.agent.name,
            retired: true,
            stopped_lifecycle,
        })
    }

    /// For a one-shot temporary agent, trigger normal graceful stop as soon as
    /// turn 1 finishes (the binding reports idle and no mail is in flight).
    /// Returns `true` if the lifecycle settled and the monitor loop should exit.
    pub(super) async fn maybe_stop_one_shot(
        &self,
        work: &mut owned::Work,
        job: &Job,
        deadline: &Deadline,
    ) -> bool {
        if !work.meta.ephemeral_one_shot
            || !work.active
            || !work.activated
            || work.session_retired
            || work.stop_key.is_some()
            || !work.mail.idle
            || work.mail.flight.is_some()
        {
            return false;
        }
        let Ok(bound) = deadline.stage(Duration::from_secs(30)) else {
            return false;
        };
        work.admission = work.cleanup_admission.clone();
        match self.stop_native(work, &bound).await {
            Ok(witness) => {
                work.last_witness = Some(witness.clone());
                match self.finish(work, witness, &bound).await {
                    Ok(()) => {
                        if !job.settled.swap(true, Ordering::AcqRel) {
                            self.activity
                                .send_modify(|count| *count = count.saturating_sub(1));
                        }
                        work.wake.event.notify_waiters();
                        work.wake.event.notify_one();
                        true
                    }
                    Err(failure) => {
                        work.cleanup_failure = Some(failure.body);
                        false
                    }
                }
            }
            Err(failure) => {
                work.cleanup_failure = Some(failure.body);
                false
            }
        }
    }

    /// Commit the single atomic `Door::Host` / owner batch containing both the
    /// automated completion notice (`MessageSent`) and `AgentRetired { Completed }`,
    /// then wake the parent agent if it is currently running. Never starves the
    /// parent stop's remaining cleanup budget; on failure or crash, startup/sweep
    /// re-derives the exact same idempotent batch.
    pub(super) async fn finalize_one_shot_completion(
        &self,
        work: &owned::Work,
        outcome: String,
        capture: se_core::ops::delegate::CaptureOutcome,
        reason: RetirementReason,
        deadline: &Deadline,
    ) {
        let Ok(remaining) = deadline.remaining() else {
            return;
        };
        let cap = (remaining / 2).min(Duration::from_secs(10));
        if cap.is_zero() {
            return;
        }
        let Ok(bound) = deadline.stage(cap) else {
            return;
        };
        if let Err(failure) = self
            .commit_one_shot_completion(
                OneShotCompletion {
                    project: work.meta.project.id.clone(),
                    agent: work.meta.agent.clone(),
                    owner: work.meta.owner.clone(),
                    child_session: work.meta.session.clone(),
                    provider: Some(work.meta.provider),
                    model: work.meta.model.clone(),
                    outcome,
                    capture,
                    reason,
                },
                &bound,
            )
            .await
        {
            eprintln!(
                "One-shot completion notice/retire deferred for {}: {}",
                work.meta.agent.id, failure.body
            );
        }
    }

    pub(super) async fn commit_one_shot_completion(
        &self,
        info: OneShotCompletion,
        deadline: &Deadline,
    ) -> Result<()> {
        let OneShotCompletion {
            project,
            agent,
            owner,
            child_session,
            provider,
            model,
            outcome,
            capture,
            reason,
        } = info;
        let admission = self.owner_project_admission(&project);
        let lookup_agent = agent.id.clone();
        let (retired, created_by) = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                let retired = cx
                    .read
                    .principal_retired(lookup_agent.clone())
                    .map_err(|e| store_error(&e))?;
                let created_by = match cx
                    .read
                    .principal(se_store::Actor::Agent(lookup_agent))
                    .map_err(|e| store_error(&e))?
                {
                    Read::Present { value } => {
                        let original = value.original.as_deref().unwrap_or(&value.current);
                        match &original.body {
                            EventBody::PrincipalRegistered { created_by, .. } => created_by.clone(),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                Ok((retired, created_by))
            })
            .await?;
        if retired {
            return Ok(());
        }
        let notify_target = std::sync::Arc::new(std::sync::Mutex::new(None));
        let capture_notify = notify_target.clone();
        self.store
            .commit(admission, deadline, None, move |kernel, cx| {
                let (batch, notify_agent) = completion_notice_batch(
                    kernel,
                    CompletionNoticeInput {
                        agent,
                        owner,
                        created_by,
                        child_session,
                        provider,
                        model,
                        outcome,
                        capture,
                        reason,
                    },
                    cx,
                )?;
                if let Ok(mut slot) = capture_notify.lock() {
                    *slot = notify_agent;
                }
                Ok(batch)
            })
            .await?;
        let recipient = notify_target.lock().ok().and_then(|slot| slot.clone());
        if let Some(parent_agent) = recipient {
            self.notify_mail_recipient(project, parent_agent)?;
        }
        Ok(())
    }

    fn notify_mail_recipient(
        &self,
        project: se_types::ProjectId,
        agent: se_types::AgentId,
    ) -> Result<()> {
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("mail wake registry", "launch registry is poisoned"))?;
        for job in jobs.values() {
            if !job.settled.load(Ordering::Acquire)
                && job.target == (project.clone(), agent.clone())
            {
                job.mail_pending.store(true, Ordering::Release);
                job.wake.event.notify_one();
            }
        }
        Ok(())
    }
}
