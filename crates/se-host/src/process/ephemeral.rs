//! Host-owned cascade stop and TTL expiry sweeps for ephemeral agents.
use super::*;
use crate::client::lease::Deadline;
use se_core::{ops::process_commit, store_error::store_error};
use se_store::{
    Actor, Admission, EphemeralAgentRecord, EventBody, RetirementReason, Scope, Snapshot,
};
use se_types::{AgentId, LifecycleId, PageRequest, ProjectId, Read, Result, SessionId};
use std::{num::NonZeroU32, sync::atomic::Ordering, time::Duration};

const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const PAGE_SIZE: u32 = 100;

impl LaunchCoordinator {
    /// Background TTL sweep so expired ephemeral agents are retired even on an
    /// otherwise-idle host. Stops cleanly once the host begins shutting down.
    pub(super) fn watch_ephemeral_ttl(self: &Arc<Self>) {
        let coordinator = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Startup already ran an initial sweep; wait one interval first.
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(current) = coordinator.upgrade() else {
                    return;
                };
                if current.stopping.load(Ordering::Acquire) {
                    return;
                }
                let swept = async {
                    let deadline = Deadline::idle()?.stage(Duration::from_secs(30))?;
                    current.sweep_ephemeral_expired(&deadline).await
                }
                .await;
                if let Err(failure) = swept {
                    eprintln!("Ephemeral TTL sweep incomplete: {}", failure.body);
                }
            }
        });
    }

    /// When a non-owner agent's session ends (outside host shutdown), stop its
    /// active ephemeral children so each child's own `SessionEnded` path finishes
    /// cleanly without retiring live helpers mid-task during `se down`.
    pub(super) async fn cascade_parent_ended(
        &self,
        project: &ProjectId,
        parent: &AgentId,
        parent_lifecycle: &LifecycleId,
        deadline: &Deadline,
    ) {
        if self.stopping.load(Ordering::Acquire) {
            return;
        }
        let Ok(bound) = deadline.stage(Duration::from_secs(15)) else {
            return;
        };
        let Ok(children) = self.all_active_ephemeral_agents(project, &bound).await else {
            return;
        };
        let parent_actor = Actor::Agent(parent.clone());
        for child in children {
            if self.stopping.load(Ordering::Acquire) || bound.remaining().is_err() {
                break;
            }
            if child.created_by.as_ref() != Some(&parent_actor) {
                continue;
            }
            if let Err(failure) = self
                .stop_ephemeral_jobs(project, &child.agent, Some(parent_lifecycle), &bound)
                .await
            {
                eprintln!(
                    "Parent-ended cascade could not stop ephemeral child {}: {}",
                    child.agent, failure.body
                );
            }
        }
    }

    /// Startup and periodic sweep: stop and retire ephemeral agents whose TTL
    /// has elapsed. Paginates all projects and all matching agents, isolates
    /// per-project errors, and never retires an agent with unwitnessed live work.
    pub(super) async fn sweep_ephemeral_expired(&self, deadline: &Deadline) -> Result<()> {
        if self.stopping.load(Ordering::Acquire) {
            return Ok(());
        }
        let now_us = crate::runtime::start::now_unix_micros()?;
        let projects = self.all_active_projects(deadline).await?;
        let mut first_failure = None;
        for project in projects {
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            deadline.remaining()?;
            if let Err(failure) = self.sweep_project_expired(&project, now_us, deadline).await {
                first_failure.get_or_insert(failure);
            }
        }
        match first_failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    async fn sweep_project_expired(
        &self,
        project: &ProjectId,
        now_us: i64,
        deadline: &Deadline,
    ) -> Result<()> {
        let active = self.all_active_ephemeral_agents(project, deadline).await?;
        let mut first_failure = None;
        for child in active {
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            let Some(ttl_seconds) = child.ttl_seconds else {
                continue;
            };
            let ttl_us = i64::from(ttl_seconds).saturating_mul(1_000_000);
            if now_us.saturating_sub(child.registered_at_us) <= ttl_us {
                continue;
            }
            deadline.remaining()?;
            if let Err(failure) = self
                .stop_ephemeral_jobs(project, &child.agent, None, deadline)
                .await
            {
                first_failure.get_or_insert(failure);
                continue;
            }
            match self
                .has_unresolved_live_work(project, &child.agent, deadline)
                .await
            {
                Ok(true) => {
                    first_failure.get_or_insert_with(|| {
                        error(
                            "ephemeral TTL sweep",
                            format!(
                                "expired ephemeral agent {} still has live or unresolved sessions/processes; leaving unretired",
                                child.agent
                            ),
                        )
                    });
                    continue;
                }
                Err(failure) => {
                    first_failure.get_or_insert(failure);
                    continue;
                }
                Ok(false) => {}
            }
            if let Err(failure) = self
                .commit_agent_retired(
                    project,
                    child.agent,
                    RetirementReason::Expired,
                    child.latest_session,
                    deadline,
                )
                .await
            {
                first_failure.get_or_insert(failure);
            }
        }
        match first_failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    async fn all_active_projects(&self, deadline: &Deadline) -> Result<Vec<ProjectId>> {
        let registry = Admission {
            scope: Scope::Registry,
            actor: Actor::Human(self.capability_admission.owner.clone()),
            session: None,
            generation: self.store.generation.get(),
        };
        let mut after = None;
        let mut ids = Vec::new();
        loop {
            deadline.remaining()?;
            let cursor = after.clone();
            let (mut batch, next) = self
                .store
                .read(registry.clone(), deadline, move |cx| {
                    let budget = se_store::ReadBudget {
                        page: PageRequest {
                            after: cursor,
                            limit: NonZeroU32::new(PAGE_SIZE)
                                .ok_or_else(|| se_types::SeError::invalid("limit", "positive"))?,
                            max_bytes: NonZeroU32::new(256 * 1024)
                                .ok_or_else(|| se_types::SeError::invalid("bytes", "positive"))?,
                        },
                        deadline: Duration::from_secs(2),
                    };
                    let page = cx.read.projects(budget).map_err(|e| store_error(&e))?;
                    let next = page.next().cloned();
                    let mut batch = Vec::new();
                    for record in page.into_items() {
                        if let EventBody::ProjectRegistered { project, .. }
                        | EventBody::ProjectUpdated { project, .. }
                        | EventBody::ProjectMoved { project, .. } = record.current.body
                        {
                            batch.push(project);
                        }
                    }
                    Ok((batch, next))
                })
                .await?;
            ids.append(&mut batch);
            match next {
                Some(cursor) => after = Some(cursor),
                None => return Ok(ids),
            }
        }
    }

    async fn all_active_ephemeral_agents(
        &self,
        project: &ProjectId,
        deadline: &Deadline,
    ) -> Result<Vec<EphemeralAgentRecord>> {
        let admission = self.owner_project_admission(project);
        let mut after_seq = None;
        let mut items = Vec::new();
        loop {
            deadline.remaining()?;
            let cursor = after_seq;
            let (mut batch, next) = self
                .store
                .read(admission.clone(), deadline, move |cx| {
                    cx.read
                        .active_ephemeral_agents(cursor, PAGE_SIZE)
                        .map_err(|e| store_error(&e))
                })
                .await?;
            items.append(&mut batch);
            match next {
                Some(seq) => after_seq = Some(seq),
                None => return Ok(items),
            }
        }
    }

    async fn has_unresolved_live_work(
        &self,
        project: &ProjectId,
        agent: &AgentId,
        deadline: &Deadline,
    ) -> Result<bool> {
        let admission = self.owner_project_admission(project);
        let target = agent.clone();
        self.store
            .read(admission, deadline, move |cx| {
                match cx
                    .read
                    .control_target(target)
                    .map_err(|e| store_error(&e))?
                {
                    Read::Present { value } => {
                        Ok(!value.sessions.is_empty() || !value.processes.is_empty())
                    }
                    Read::Absent { .. } => Ok(false),
                    other => {
                        se_core::scope::require_present(
                            other,
                            "ephemeral retirement control check",
                            "Restore control target metadata before retiring this agent.",
                        )?;
                        Ok(true)
                    }
                }
            })
            .await
    }

    fn owner_project_admission(&self, project: &ProjectId) -> Admission {
        Admission {
            scope: Scope::Project(project.clone()),
            actor: Actor::Human(self.capability_admission.owner.clone()),
            session: None,
            generation: self.store.generation.get(),
        }
    }

    /// Filter jobs by `(project, agent)` and `exclude_lifecycle` BEFORE locking
    /// any `job.state` mutex so a parent's retirement never self-deadlocks.
    async fn stop_ephemeral_jobs(
        &self,
        project: &ProjectId,
        agent: &AgentId,
        exclude_lifecycle: Option<&LifecycleId>,
        deadline: &Deadline,
    ) -> Result<()> {
        let matching: Vec<_> = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("ephemeral cascade stop", "launch registry is poisoned"))?
            .values()
            .filter(|job| {
                !job.settled.load(Ordering::Acquire)
                    && &job.target.0 == project
                    && &job.target.1 == agent
                    && exclude_lifecycle != Some(&job.lifecycle)
            })
            .cloned()
            .collect();
        for job in matching {
            let mut work = crate::runtime::pool::within(deadline, job.state.lock()).await?;
            if !work.released && !work.session_retired {
                work.admission = work.cleanup_admission.clone();
                if !work.active {
                    self.cleanup_failed(&mut work, deadline).await?;
                } else {
                    let witness = self.stop_native(&mut work, deadline).await?;
                    work.last_witness = Some(witness.clone());
                    self.finish(&mut work, witness, deadline).await?;
                }
                if !job.settled.swap(true, Ordering::AcqRel) {
                    self.activity
                        .send_modify(|count| *count = count.saturating_sub(1));
                }
            }
            work.wake.event.notify_waiters();
            work.wake.event.notify_one();
        }
        Ok(())
    }

    async fn commit_agent_retired(
        &self,
        project: &ProjectId,
        agent: AgentId,
        reason: RetirementReason,
        final_session: Option<SessionId>,
        deadline: &Deadline,
    ) -> Result<()> {
        let admission = self.owner_project_admission(project);
        let target = agent.clone();
        let retired = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                cx.read
                    .principal_retired(target)
                    .map_err(|e| store_error(&e))
            })
            .await?;
        if retired {
            return Ok(());
        }
        self.store
            .commit(admission, deadline, None, move |kernel, cx| {
                process_commit::retire_agent(kernel, agent, reason, final_session, cx)
            })
            .await?;
        Ok(())
    }
}
