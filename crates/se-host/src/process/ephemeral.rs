//! Host-owned cascade stop and TTL expiry sweeps for ephemeral agents.
use super::*;
use crate::client::lease::Deadline;
use se_core::{ops::process_commit, store_error::store_error};
use se_store::{Actor, Admission, EventBody, RetirementReason, Scope, Snapshot};
use se_types::{AgentId, PageRequest, ProjectId, Result, SessionId};
use std::{num::NonZeroU32, sync::atomic::Ordering, time::Duration};

impl LaunchCoordinator {
    /// When a non-owner agent's session ends, stop its active ephemeral children
    /// (allowing each child's own `SessionEnded` path to finish cleanly) and retire them.
    pub(super) async fn cascade_parent_ended(
        &self,
        project: &ProjectId,
        parent: &AgentId,
        deadline: &Deadline,
    ) {
        let Ok(bound) = deadline.stage(Duration::from_secs(15)) else {
            return;
        };
        let admission = self.owner_project_admission(project);
        let children = match self
            .store
            .read(admission.clone(), &bound, |cx| {
                cx.read
                    .active_ephemeral_agents()
                    .map_err(|e| store_error(&e))
            })
            .await
        {
            Ok(items) => items,
            Err(_) => return,
        };
        let parent_actor = Actor::Agent(parent.clone());
        for child in children {
            if child.created_by.as_ref() != Some(&parent_actor) {
                continue;
            }
            if bound.remaining().is_err() {
                break;
            }
            let _ = self
                .stop_ephemeral_jobs(project, &child.agent, &bound)
                .await;
            let _ = self
                .commit_agent_retired(
                    project,
                    child.agent,
                    RetirementReason::ParentEnded,
                    child.latest_session,
                    &bound,
                )
                .await;
        }
    }

    /// Startup and periodic sweep: stop and retire ephemeral agents whose TTL has elapsed.
    pub(super) async fn sweep_ephemeral_expired(&self, deadline: &Deadline) -> Result<()> {
        let now_us = crate::runtime::start::now_unix_micros()?;
        let registry = Admission {
            scope: Scope::Registry,
            actor: Actor::Human(self.capability_admission.owner.clone()),
            session: None,
            generation: self.store.generation.get(),
        };
        let projects = self
            .store
            .read(registry, deadline, |cx| {
                let budget = se_store::ReadBudget {
                    page: PageRequest {
                        after: None,
                        limit: NonZeroU32::new(100)
                            .ok_or_else(|| se_types::SeError::invalid("limit", "positive"))?,
                        max_bytes: NonZeroU32::new(256 * 1024)
                            .ok_or_else(|| se_types::SeError::invalid("bytes", "positive"))?,
                    },
                    deadline: Duration::from_secs(2),
                };
                let page = cx.read.projects(budget).map_err(|e| store_error(&e))?;
                let mut ids = Vec::new();
                for record in page.into_items() {
                    if let EventBody::ProjectRegistered { project, .. }
                    | EventBody::ProjectUpdated { project, .. }
                    | EventBody::ProjectMoved { project, .. } = record.current.body
                    {
                        ids.push(project);
                    }
                }
                Ok(ids)
            })
            .await?;
        for project in projects {
            deadline.remaining()?;
            let admission = self.owner_project_admission(&project);
            let active = self
                .store
                .read(admission, deadline, |cx| {
                    cx.read
                        .active_ephemeral_agents()
                        .map_err(|e| store_error(&e))
                })
                .await?;
            for child in active {
                let Some(ttl_seconds) = child.ttl_seconds else {
                    continue;
                };
                let ttl_us = i64::from(ttl_seconds).saturating_mul(1_000_000);
                if now_us.saturating_sub(child.registered_at_us) <= ttl_us {
                    continue;
                }
                deadline.remaining()?;
                let _ = self
                    .stop_ephemeral_jobs(&project, &child.agent, deadline)
                    .await;
                let _ = self
                    .commit_agent_retired(
                        &project,
                        child.agent,
                        RetirementReason::Expired,
                        child.latest_session,
                        deadline,
                    )
                    .await;
            }
        }
        Ok(())
    }

    fn owner_project_admission(&self, project: &ProjectId) -> Admission {
        Admission {
            scope: Scope::Project(project.clone()),
            actor: Actor::Human(self.capability_admission.owner.clone()),
            session: None,
            generation: self.store.generation.get(),
        }
    }

    async fn stop_ephemeral_jobs(
        &self,
        project: &ProjectId,
        agent: &AgentId,
        deadline: &Deadline,
    ) -> Result<()> {
        let matching: Vec<_> = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("ephemeral cascade stop", "launch registry is poisoned"))?
            .values()
            .filter(|job| !job.settled.load(Ordering::Acquire))
            .cloned()
            .collect();
        for job in matching {
            let mut work = crate::runtime::pool::within(deadline, job.state.lock()).await?;
            if &work.meta.project.id != project || &work.meta.agent.id != agent {
                continue;
            }
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
