//! Host-owned cascade stop and TTL expiry sweeps for ephemeral agents.
use super::*;
use crate::client::lease::Deadline;
use se_core::{ops::process_commit, store_error::store_error};
use se_store::{
    Actor, Admission, EphemeralAgentRecord, EventBody, RetirementReason, Scope, Snapshot,
};
use se_types::{AgentId, LifecycleId, PageRequest, ProjectId, Read, Result, SessionId};
use std::{num::NonZeroU32, sync::atomic::Ordering, time::Duration};

pub(super) const SWEEP_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const PAGE_SIZE: u32 = 100;

/// Single deadline-driven timer slot for ephemeral TTL sweeps. When `running`
/// is false, no background task is active (zero idle wakeups or open read
/// connections). A monotonic `generation` counter prevents disarming when a
/// new TTL child registers concurrently during an active sweep.
struct TtlTimerState {
    next_deadline: Option<tokio::time::Instant>,
    generation: u64,
    running: bool,
}

pub(super) struct TtlTimer {
    state: std::sync::Mutex<TtlTimerState>,
    wake: tokio::sync::Notify,
}

impl TtlTimer {
    pub(super) fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(TtlTimerState {
                next_deadline: None,
                generation: 0,
                running: false,
            }),
            wake: tokio::sync::Notify::new(),
        }
    }
}

impl LaunchCoordinator {
    /// Arm or shorten the host's single deadline-driven TTL sweeper.
    /// Spawns a background task only when none is currently active; if a timer
    /// is already sleeping or sweeping, bumps `generation`, records the
    /// earliest deadline, and notifies the waiter.
    pub(super) fn arm_ephemeral_ttl(self: &Arc<Self>, delay: Duration) {
        if self.stopping.load(Ordering::Acquire) {
            return;
        }
        let target = tokio::time::Instant::now() + delay;
        let should_spawn = {
            let Ok(mut state) = self.ephemeral_ttl.state.lock() else {
                return;
            };
            state.generation = state.generation.wrapping_add(1);
            state.next_deadline = Some(match state.next_deadline {
                Some(existing) => existing.min(target),
                None => target,
            });
            if !state.running {
                state.running = true;
                true
            } else {
                drop(state);
                self.ephemeral_ttl.wake.notify_one();
                false
            }
        };
        if !should_spawn {
            return;
        }
        let coordinator = Arc::downgrade(self);
        tokio::spawn(run_ephemeral_ttl_loop(coordinator));
    }

    /// When a non-owner agent's session ends (outside host shutdown), stop its
    /// active ephemeral children so each child's own `SessionEnded` path finishes
    /// cleanly without retiring live helpers mid-task during `se down`.
    /// Caps cascade work at half of the parent's remaining stop budget (at most
    /// 15s) and never propagates errors, so `retire_files` and native release
    /// always keep enough budget to settle the parent.
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
        let Ok(remaining) = deadline.remaining() else {
            return;
        };
        let cap = (remaining / 2).min(Duration::from_secs(15));
        if cap.is_zero() {
            return;
        }
        let Ok(bound) = deadline.stage(cap) else {
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
                .stop_ephemeral_jobs(
                    project,
                    &child.agent,
                    Some(parent_lifecycle),
                    owned::OneShotExit::ParentEnded,
                    &bound,
                )
                .await
            {
                eprintln!(
                    "Parent-ended cascade could not stop ephemeral child {}: {}",
                    child.agent, failure.body
                );
            }
        }
    }

    /// Startup and deadline-driven sweep: stop and retire ephemeral agents whose
    /// TTL has elapsed, returning the earliest remaining wait duration among any
    /// still-active TTL agents (or `None` when none remain). Paginates all
    /// projects and matching agents, isolates per-project errors, and never
    /// retires an agent with unwitnessed live work.
    pub(super) async fn sweep_ephemeral_expired(
        &self,
        deadline: &Deadline,
    ) -> Result<Option<Duration>> {
        if self.stopping.load(Ordering::Acquire) {
            return Ok(None);
        }
        let now_us = crate::runtime::start::now_unix_micros()?;
        let projects = self.all_active_projects(deadline).await?;
        let mut first_failure = None;
        let mut next_delay: Option<Duration> = None;
        for project in projects {
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            deadline.remaining()?;
            match self.sweep_project_expired(&project, now_us, deadline).await {
                Ok(Some(delay)) => {
                    next_delay = Some(match next_delay {
                        Some(current) => current.min(delay),
                        None => delay,
                    });
                }
                Ok(None) => {}
                Err(failure) => {
                    first_failure.get_or_insert(failure);
                }
            }
        }
        match first_failure {
            Some(failure) => Err(failure),
            None => Ok(next_delay),
        }
    }

    async fn sweep_project_expired(
        &self,
        project: &ProjectId,
        now_us: i64,
        deadline: &Deadline,
    ) -> Result<Option<Duration>> {
        let active = self.all_active_ephemeral_agents(project, deadline).await?;
        let mut first_failure = None;
        let mut next_delay: Option<Duration> = None;
        for child in active {
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            if child.one_shot
                && let Some(session_id) = &child.latest_session
                && self
                    .finish_ended_one_shot(project, &child.agent, session_id, deadline)
                    .await?
            {
                continue;
            }
            let Some(ttl_seconds) = child.ttl_seconds else {
                continue;
            };
            let ttl_us = i64::from(ttl_seconds).saturating_mul(1_000_000);
            let elapsed_us = now_us.saturating_sub(child.registered_at_us);
            if elapsed_us <= ttl_us {
                let remaining_us = ttl_us.saturating_sub(elapsed_us);
                let wait = Duration::from_micros(u64::try_from(remaining_us).unwrap_or(0))
                    .saturating_add(Duration::from_millis(100));
                next_delay = Some(match next_delay {
                    Some(current) => current.min(wait),
                    None => wait,
                });
                continue;
            }
            deadline.remaining()?;
            if let Err(failure) = self
                .stop_ephemeral_jobs(
                    project,
                    &child.agent,
                    None,
                    owned::OneShotExit::Expired,
                    deadline,
                )
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
            None => Ok(next_delay),
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

    /// Crash-recovery re-derivation (`B3`): if a one-shot temporary agent's
    /// latest session has already committed `SessionEnded` (with no live
    /// sessions or processes remaining) but `retired_seq` is still NULL, commit
    /// the exact same idempotent completion notice + `AgentRetired { Completed }`
    /// batch. Returns `Ok(true)` if the child was finalized.
    async fn finish_ended_one_shot(
        &self,
        project: &ProjectId,
        agent: &AgentId,
        session: &SessionId,
        deadline: &Deadline,
    ) -> Result<bool> {
        let admission = self.owner_project_admission(project);
        let target_agent = agent.clone();
        let target_session = session.clone();
        let owner = self.capability_admission.owner.clone();
        let project_id = project.clone();
        let recovered = self
            .store
            .read(admission, deadline, move |cx| {
                let Read::Present { value: control } = cx
                    .read
                    .control_target(target_agent.clone())
                    .map_err(|e| store_error(&e))?
                else {
                    return Ok(None);
                };
                if control.retired || !control.sessions.is_empty() || !control.processes.is_empty()
                {
                    return Ok(None);
                }
                let Read::Present {
                    value: session_head,
                } = cx
                    .read
                    .session(target_session.clone())
                    .map_err(|e| store_error(&e))?
                else {
                    return Ok(None);
                };
                let EventBody::SessionEnded { reason, .. } = &session_head.current.body else {
                    return Ok(None);
                };
                let outcome = match reason {
                    se_store::StoredText::Present(text) => text.clone(),
                    _ => "session ended".to_owned(),
                };
                let Some(retirement_reason) = classify_ended_reason(&outcome) else {
                    return Ok(None);
                };
                let prepared = session_head
                    .original
                    .as_deref()
                    .unwrap_or(&session_head.current);
                let capture_enabled = matches!(
                    prepared.body,
                    EventBody::SessionPrepared {
                        consent: se_store::Consent::Capture,
                        ..
                    }
                );
                let (activated, capture) =
                    inspect_session_completion(cx.read, &target_session, capture_enabled)?;
                if !activated {
                    return Ok(None);
                }
                let name = match &control.principal.current.body {
                    EventBody::PrincipalRegistered { name, .. }
                    | EventBody::PrincipalRenamed { name, .. } => name.clone(),
                    _ => target_agent.as_str().to_owned(),
                };
                let (provider, model) = match control.profile {
                    Read::Present { value } => match value.current.body {
                        EventBody::ProfileSaved { profile, .. } => {
                            (Some(profile.provider), profile.model)
                        }
                        _ => (None, None),
                    },
                    _ => (None, None),
                };
                Ok(Some(super::delegate::OneShotCompletion {
                    project: project_id,
                    agent: se_types::Named {
                        id: target_agent,
                        name,
                    },
                    owner,
                    child_session: target_session,
                    provider,
                    model,
                    outcome,
                    capture,
                    reason: retirement_reason,
                }))
            })
            .await?;
        let Some(info) = recovered else {
            return Ok(false);
        };
        self.commit_one_shot_completion(info, deadline).await?;
        Ok(true)
    }

    pub(super) async fn has_unresolved_live_work(
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

    pub(super) fn owner_project_admission(&self, project: &ProjectId) -> Admission {
        Admission {
            scope: Scope::Project(project.clone()),
            actor: Actor::Human(self.capability_admission.owner.clone()),
            session: None,
            generation: self.store.generation.get(),
        }
    }

    /// Filter jobs by `(project, agent)` and `exclude_lifecycle` BEFORE locking
    /// any `job.state` mutex so a parent's retirement never self-deadlocks.
    /// Returns `true` if at least one active lifecycle job was stopped.
    pub(super) async fn stop_ephemeral_jobs(
        &self,
        project: &ProjectId,
        agent: &AgentId,
        exclude_lifecycle: Option<&LifecycleId>,
        exit_kind: owned::OneShotExit,
        deadline: &Deadline,
    ) -> Result<bool> {
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
        let mut stopped = false;
        for job in matching {
            let mut work = crate::runtime::pool::within(deadline, job.state.lock()).await?;
            if !work.released && !work.session_retired {
                work.one_shot_exit = exit_kind;
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
                stopped = true;
            }
            work.wake.event.notify_waiters();
            work.wake.event.notify_one();
        }
        Ok(stopped)
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

async fn run_ephemeral_ttl_loop(coordinator: std::sync::Weak<LaunchCoordinator>) {
    let mut last_warning: Option<String> = None;
    loop {
        let Some(current) = coordinator.upgrade() else {
            return;
        };
        if current.stopping.load(Ordering::Acquire) {
            if let Ok(mut state) = current.ephemeral_ttl.state.lock() {
                state.next_deadline = None;
                state.running = false;
            }
            return;
        }
        let (target, gen_before) = {
            let Ok(mut state) = current.ephemeral_ttl.state.lock() else {
                return;
            };
            match state.next_deadline {
                Some(t) => (t, state.generation),
                None => {
                    state.running = false;
                    return;
                }
            }
        };
        let woken_early = tokio::select! {
            () = tokio::time::sleep_until(target) => false,
            () = current.ephemeral_ttl.wake.notified() => true,
        };
        if woken_early {
            continue;
        }
        if current.stopping.load(Ordering::Acquire) {
            if let Ok(mut state) = current.ephemeral_ttl.state.lock() {
                state.next_deadline = None;
                state.running = false;
            }
            return;
        }
        let swept = async {
            let deadline = Deadline::idle()?.stage(Duration::from_secs(30))?;
            current.sweep_ephemeral_expired(&deadline).await
        }
        .await;
        let now = tokio::time::Instant::now();
        let Ok(mut state) = current.ephemeral_ttl.state.lock() else {
            return;
        };
        let dirty = state.generation != gen_before;
        match swept {
            Ok(Some(next_delay)) => {
                last_warning = None;
                let candidate = now + next_delay;
                state.next_deadline = Some(if dirty {
                    state.next_deadline.map_or(candidate, |d| d.min(candidate))
                } else {
                    candidate
                });
            }
            Ok(None) => {
                if !dirty {
                    state.next_deadline = None;
                    state.running = false;
                    return;
                }
            }
            Err(failure) => {
                let msg = failure.body.to_string();
                if last_warning.as_deref() != Some(msg.as_str()) {
                    eprintln!("Ephemeral TTL sweep incomplete: {msg}");
                    last_warning = Some(msg);
                }
                let retry = now + SWEEP_RETRY_INTERVAL;
                state.next_deadline = Some(if dirty {
                    state.next_deadline.map_or(retry, |d| d.min(retry))
                } else {
                    retry
                });
            }
        }
    }
}

fn classify_ended_reason(outcome: &str) -> Option<RetirementReason> {
    if outcome == process_commit::ENDED_BY_REBOOT
        || outcome == "launch preparation failed"
        || outcome == se_core::ops::agent_launch::ATTENDED_RECONNECT_FAILED
    {
        return None;
    }
    Some(if outcome.starts_with("parent session ended") {
        RetirementReason::ParentEnded
    } else if outcome.starts_with("delegation cancelled") {
        RetirementReason::Cancelled
    } else if outcome.starts_with("ephemeral TTL expired") {
        RetirementReason::Expired
    } else {
        RetirementReason::Completed
    })
}

fn inspect_session_completion<R: Snapshot>(
    read: &mut R,
    session: &SessionId,
    capture_enabled: bool,
) -> Result<(bool, se_core::ops::delegate::CaptureOutcome)> {
    use se_core::ops::delegate::CaptureOutcome;
    let mut after = None;
    let mut activated = false;
    let mut capture = if capture_enabled {
        CaptureOutcome::Incomplete
    } else {
        CaptureOutcome::Disabled
    };
    loop {
        let budget = se_store::ReadBudget {
            page: PageRequest {
                after: after.clone(),
                limit: NonZeroU32::new(64)
                    .ok_or_else(|| se_types::SeError::invalid("limit", "positive"))?,
                max_bytes: NonZeroU32::new(256 * 1024)
                    .ok_or_else(|| se_types::SeError::invalid("bytes", "positive"))?,
            },
            deadline: Duration::from_secs(2),
        };
        let page = read
            .history(
                se_store::HistoryQuery {
                    agent: None,
                    kinds: vec![
                        se_store::EventKind::SessionActivated,
                        se_store::EventKind::CaptureVerified,
                        se_store::EventKind::CaptureFailed,
                    ],
                    families: Vec::new(),
                    session: Some(session.clone()),
                    transcript: se_store::TranscriptFilter::All,
                    since: None,
                    direction: se_store::HistoryDirection::OldestFirst,
                },
                budget,
            )
            .map_err(|e| store_error(&e))?;
        let next = page.next().cloned();
        for event in page.into_items() {
            match event.body {
                EventBody::SessionActivated { .. } => activated = true,
                EventBody::CaptureVerified { .. } if capture_enabled => {
                    capture = CaptureOutcome::Verified;
                }
                EventBody::CaptureFailed { .. } if capture_enabled => {
                    capture = CaptureOutcome::Incomplete;
                }
                _ => {}
            }
        }
        match next {
            Some(cursor) => after = Some(cursor),
            None => return Ok((activated, capture)),
        }
    }
}
