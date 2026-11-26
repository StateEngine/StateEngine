//! Atomic host-writer lifecycle operations for external seats: approve, revoke,
//! expiry reconciliation, and lease-generation-fenced disconnect cleanup.
use super::{commit, *};
use crate::{
    HostedRouter,
    client::lease::Deadline,
    runtime::{ExecutionContext, WriteIdentity, start::now_unix_micros, submit},
};
use se_core::store_error::store_error;
use se_store::{Actor, Admission, EventBody, Scope, Snapshot};
use se_types::{AgentId, HumanId, ProjectId, Read, Result, SeError, Secret, SessionId};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const EXPIRED_LEASE_REASON: &str = "external seat lease expired";
pub(crate) use commit::resolve_external_agent;

/// Durably revoke any expired external leases still tracked in this host's registry.
/// Propagates reconciliation failures so callers never conceal a still-active row.
pub(crate) async fn reconcile_expired_leases(
    router: &HostedRouter,
    project: Option<&ProjectId>,
) -> Result<usize> {
    let deadline = crate::runtime::serve::options(std::time::Duration::from_secs(10))?;
    reconcile_expired_on_execution(
        &router.execution,
        &router.context.owner,
        project,
        None,
        &deadline,
    )
    .await
}

/// Shared durable expiry reconciliation usable by external RPCs, `se status`/`agent show`,
/// and managed `se launch` before checking live sessions.
pub(crate) async fn reconcile_expired_on_execution(
    execution: &ExecutionContext,
    owner: &HumanId,
    project: Option<&ProjectId>,
    agent_filter: Option<&AgentId>,
    deadline: &Deadline,
) -> Result<usize> {
    let now_us = now_unix_micros()?;
    let expired = execution.external.expired_leases(project, now_us)?;
    let mut reconciled = 0usize;
    for lease in expired {
        if agent_filter.is_some_and(|a| a != &lease.agent_id) {
            continue;
        }
        let _guard = execution
            .external
            .agent_lock(&lease.project_id, &lease.agent_id)?
            .lock_owned()
            .await;
        if fenced_disconnect_locked_on_execution(
            execution,
            owner,
            &lease.project_id,
            &lease.agent_id,
            &lease.session_id,
            lease.lease_generation,
            EXPIRED_LEASE_REASON,
            deadline,
        )
        .await?
        {
            reconciled += 1;
        }
    }
    Ok(reconciled)
}

async fn revoke_expired_lease_on_store(
    store: &crate::runtime::store::Store,
    external: &ExternalRegistry,
    owner: &HumanId,
    lease: &ActiveLease,
    deadline: &Deadline,
) -> Result<bool> {
    let reads = store.reads.clone();
    let generation = store.generation;
    let owner_cloned = owner.clone();
    let project = lease.project_id.clone();
    let target_session = lease.session_id.clone();
    let rev_info = store
        .pool
        .run_owned(deadline, move || {
            let phase = reads.read_phase().map_err(|e| store_error(&e))?;
            let admission = Admission {
                scope: Scope::Project(project),
                actor: Actor::Human(owner_cloned),
                session: None,
                generation: generation.get(),
            };
            let mut snap = phase
                .into_snapshot(se_core::admission::read_scope(&admission))
                .map_err(|e| store_error(&e))?;
            let res = match snap.session(target_session).map_err(|e| store_error(&e)) {
                Ok(Read::Present { value })
                    if matches!(
                        value.current.body,
                        EventBody::SessionPrepared { .. } | EventBody::SessionActivated { .. }
                    ) =>
                {
                    Ok(Some(value.revision))
                }
                Ok(_) => Ok(None),
                Err(e) => Err(e),
            };
            crate::runtime::executor::close_read(res, snap.close())
        })
        .await?;
    if let Some(session_rev) = rev_info {
        let warn = commit::commit_revocation_on_store(
            store,
            owner,
            &lease.project_id,
            &lease.session_id,
            session_rev,
            Some((lease.credential_id, commit::rev(2))),
            EXPIRED_LEASE_REASON,
            deadline,
        )
        .await?;
        let _ = external.remove_if_matching(
            &lease.project_id,
            &lease.agent_id,
            &lease.session_id,
            lease.lease_generation,
        )?;
        if let Some(err) = warn {
            return Err(err);
        }
        Ok(true)
    } else {
        let _ = external.remove_if_matching(
            &lease.project_id,
            &lease.agent_id,
            &lease.session_id,
            lease.lease_generation,
        )?;
        Ok(false)
    }
}

/// Reconcile any expired or stale-generation external seat for one agent before
/// a managed `se launch` evaluates whether live takeover is required.
pub(crate) async fn reconcile_external_for_launch_on_store(
    store: &crate::runtime::store::Store,
    external: &ExternalRegistry,
    owner: &HumanId,
    project_id: &ProjectId,
    agent_id: &AgentId,
    deadline: &Deadline,
) -> Result<bool> {
    let _guard = external
        .agent_lock(project_id, agent_id)?
        .lock_owned()
        .await;
    let now_us = now_unix_micros()?;
    let mut changed = false;
    for lease in external.expired_leases(Some(project_id), now_us)? {
        if lease.agent_id == *agent_id
            && revoke_expired_lease_on_store(store, external, owner, &lease, deadline).await?
        {
            changed = true;
        }
    }
    let reads = store.reads.clone();
    let generation = store.generation.get();
    let project = project_id.clone();
    let agent = agent_id.clone();
    let owner_cloned = owner.clone();
    let check = store
        .pool
        .run_owned(deadline, move || {
            let phase = reads.read_phase().map_err(|e| store_error(&e))?;
            commit::inspect_live_seat(phase, &project, &owner_cloned, generation, &agent)
        })
        .await?;
    if let commit::LiveSeatCheck::StaleExternal(stale, reason) = check {
        let warn = commit::commit_revocation_on_store(
            store,
            owner,
            project_id,
            &stale.session_id,
            stale.session_rev,
            stale.cred,
            reason,
            deadline,
        )
        .await?;
        if let Some(err) = warn {
            return Err(err);
        }
        changed = true;
    }
    Ok(changed)
}

async fn ensure_agent_clear_locked(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    deadline: &Deadline,
) -> Result<()> {
    let now_us = now_unix_micros()?;
    for lease in router
        .execution
        .external
        .expired_leases(Some(project_id), now_us)?
    {
        if lease.agent_id == *agent_id {
            fenced_disconnect_locked_on_execution(
                &router.execution,
                &router.context.owner,
                &lease.project_id,
                &lease.agent_id,
                &lease.session_id,
                lease.lease_generation,
                EXPIRED_LEASE_REASON,
                deadline,
            )
            .await?;
        }
    }
    let context = router.context.clone();
    let project = project_id.clone();
    let agent = agent_id.clone();
    let live_check = router
        .execution
        .blocking
        .run_owned(deadline, move || {
            let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
            if let Err(error) = context.check_generation(&phase) {
                return crate::runtime::executor::close_read(Err(error), phase.close());
            }
            commit::inspect_live_seat(
                phase,
                &project,
                &context.owner,
                context.generation.get(),
                &agent,
            )
        })
        .await?;
    match live_check {
        commit::LiveSeatCheck::Clear => Ok(()),
        commit::LiveSeatCheck::StaleExternal(stale, reason) => {
            if let Some(warn) = commit::commit_revocation(
                router,
                project_id,
                &stale.session_id,
                stale.session_rev,
                stale.cred,
                reason,
                deadline,
            )
            .await?
            {
                return Err(warn);
            }
            Ok(())
        }
        commit::LiveSeatCheck::LiveConflict(remedy) => {
            Err(SeError::invalid("external seat approval", remedy))
        }
    }
}

/// Owner approves a pending claim once. Serialized per `(project_id, agent_id)`
/// from preflight through registry publication and bridge handoff, and retained
/// through the writer's authoritative durable outcome.
pub(crate) async fn approve_claim(
    router: &HostedRouter,
    claim_id: &str,
    deadline: &Deadline,
) -> Result<ExternalApproveOutput> {
    router.check_open()?;
    let host_generation = router.context.generation;
    let peeked = router
        .execution
        .external
        .peek_claim(claim_id, host_generation)?;
    let _agent_guard = router
        .execution
        .external
        .agent_lock(&peeked.project_id, &peeked.agent_id)?
        .lock_owned()
        .await;
    ensure_agent_clear_locked(router, &peeked.project_id, &peeked.agent_id, deadline).await?;
    let consumed = router
        .execution
        .external
        .consume_claim(claim_id, host_generation)?;
    let lease_generation = router.execution.external.allocate_lease_generation();
    let now_us = now_unix_micros()?;
    let expires_at_us = now_us
        .checked_add((EXTERNAL_LEASE_TTL_SECS as i64) * 1_000_000)
        .ok_or_else(|| SeError::invalid("external lease expiry", "clock overflow"))?;

    let raw_nonce = crate::client::auth::fresh_nonce()?;
    let token_str = format!("sext1.{}", se_types::hex_lower(&raw_nonce));
    let secret = Arc::new(Secret::new(token_str.as_bytes().to_vec())?);
    let secret_sha256: [u8; 32] = Sha256::digest(secret.expose()).into();

    let (batch, session_id, credential_id, key) = commit::build_approve_batch(
        router,
        &consumed,
        lease_generation,
        now_us,
        expires_at_us,
        secret_sha256,
        deadline,
    )
    .await?;

    let identity = WriteIdentity {
        operation: "external.approve",
        key: Some(key),
        natural_key: None,
        natural_events: Vec::new(),
    };
    let active = ActiveLease {
        project_id: consumed.project_id.clone(),
        agent_id: consumed.agent_id.clone(),
        agent_name: consumed.agent_name.clone(),
        session_id: session_id.clone(),
        credential_id,
        lease_generation,
        peer_pid: consumed.peer_pid,
        host_generation,
        expires_at_us,
        reconcile_required: false,
    };
    let observer_warning =
        settle_approve_commit(router, batch, &identity, &active, deadline).await?;
    router.execution.external.record_active_lease(active)?;
    let output = handoff_to_bridge_locked(
        router,
        consumed,
        session_id,
        lease_generation,
        expires_at_us,
        secret,
    )
    .await?;
    if let Some(warn) = observer_warning {
        return Err(warn);
    }
    Ok(output)
}

async fn settle_approve_commit(
    router: &HostedRouter,
    batch: se_store::AtomicBatch,
    identity: &WriteIdentity,
    active: &ActiveLease,
    deadline: &Deadline,
) -> Result<Option<SeError>> {
    match submit::submit_retained(&router.execution, batch, identity, deadline).await? {
        submit::RetainedCommit::Committed { observer_warning } => Ok(observer_warning),
        submit::RetainedCommit::OutcomeUnknown(err) => {
            let check_deadline =
                crate::runtime::serve::options(std::time::Duration::from_secs(10))?;
            match commit::session_is_active(
                &router.execution,
                &router.context.owner,
                &active.project_id,
                &active.session_id,
                &check_deadline,
            )
            .await
            {
                Ok(true) => Ok(None),
                Ok(false) => Err(err),
                Err(read_err) => {
                    let mut pending = active.clone();
                    pending.reconcile_required = true;
                    let _ = router.execution.external.record_active_lease(pending);
                    Err(err.with_cause(read_err))
                }
            }
        }
    }
}

async fn handoff_to_bridge_locked(
    router: &HostedRouter,
    consumed: registry::ConsumedClaim,
    session_id: SessionId,
    lease_generation: u64,
    expires_at_us: i64,
    secret: Arc<Secret>,
) -> Result<ExternalApproveOutput> {
    let handoff_ok = {
        let mut bridge = consumed
            .bridge
            .lock()
            .map_err(|_| se_core::scope::unreadable("external bridge binding", "lock poisoned"))?;
        if bridge.closed {
            false
        } else {
            bridge.active = Some((
                consumed.project_id.clone(),
                consumed.agent_id.clone(),
                session_id.clone(),
                lease_generation,
            ));
            true
        }
    };
    let delivered = handoff_ok
        && consumed
            .delivery
            .send(ClaimApprovalDelivery {
                project_id: consumed.project_id.clone(),
                agent_id: consumed.agent_id.clone(),
                agent_name: consumed.agent_name.clone(),
                session_id: session_id.clone(),
                lease_generation,
                expires_at_us,
                secret,
            })
            .is_ok();
    if !delivered {
        match fenced_disconnect_locked_with_retry(
            router,
            &consumed.project_id,
            &consumed.agent_id,
            &session_id,
            lease_generation,
            "external bridge disconnected before capability delivery",
        )
        .await
        {
            Ok(_) => {
                if let Ok(mut b) = consumed.bridge.lock()
                    && b.active
                        .as_ref()
                        .is_some_and(|(_, _, s, g)| *s == session_id && *g == lease_generation)
                {
                    b.active = None;
                }
                return Err(SeError::invalid(
                    "external claim approval",
                    "a still-connected bridge waiting on this claim; the bridge disconnected so the seat was revoked",
                ));
            }
            Err(revoke_err) => {
                router.execution.external.mark_reconcile_required(
                    &consumed.project_id,
                    &consumed.agent_id,
                    &session_id,
                    lease_generation,
                );
                return Err(SeError::invalid(
                    "external claim approval",
                    "a still-connected bridge waiting on this claim; the bridge disconnected and rollback could not be confirmed, so run `se external revoke`",
                )
                .with_cause(revoke_err));
            }
        }
    }
    Ok(ExternalApproveOutput {
        claim_id: consumed.claim_id,
        project_id: consumed.project_id,
        agent_id: consumed.agent_id,
        agent_name: consumed.agent_name,
        session_id,
        lease_generation,
        expires_at_us,
    })
}

/// Owner revokes an active external seat by agent name or ID, serialized per agent.
pub(crate) async fn revoke_seat(
    router: &HostedRouter,
    project: ProjectId,
    agent_selector: &str,
    reason: &str,
    deadline: &Deadline,
) -> Result<ExternalRevokeOutput> {
    router.check_open()?;
    let agent_id = {
        let context = router.context.clone();
        let project = project.clone();
        let selector = agent_selector.to_owned();
        router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
                if let Err(error) = context.check_generation(&phase) {
                    return crate::runtime::executor::close_read(Err(error), phase.close());
                }
                let (agent_id, _, _) = resolve_external_agent(
                    phase,
                    &project,
                    &context.owner,
                    context.generation.get(),
                    &selector,
                    false,
                )?;
                Ok(agent_id)
            })
            .await?
    };
    let _agent_guard = router
        .execution
        .external
        .agent_lock(&project, &agent_id)?
        .lock_owned()
        .await;
    let active = {
        let context = router.context.clone();
        let project = project.clone();
        let agent = agent_id.clone();
        router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
                if let Err(error) = context.check_generation(&phase) {
                    return crate::runtime::executor::close_read(Err(error), phase.close());
                }
                commit::find_active_external_session(
                    phase,
                    &project,
                    &context.owner,
                    context.generation.get(),
                    &agent,
                )
            })
            .await?
    };

    let observer_warning = commit::commit_revocation(
        router,
        &project,
        &active.session_id,
        active.session_rev,
        active.cred,
        reason,
        deadline,
    )
    .await?;

    let removed = match active.lease_generation {
        Some(lease_gen) => router.execution.external.remove_if_matching(
            &project,
            &agent_id,
            &active.session_id,
            lease_gen,
        )?,
        None => {
            router
                .execution
                .external
                .remove_if_session(&project, &agent_id, &active.session_id)?
        }
    };
    if let Some(warn) = observer_warning {
        return Err(warn);
    }
    let lease_generation = removed
        .as_ref()
        .map(|lease| lease.lease_generation)
        .or(active.lease_generation);

    Ok(ExternalRevokeOutput {
        project_id: project,
        agent_id,
        session_id: active.session_id,
        lease_generation,
        revoked: true,
    })
}

/// Bounded retry wrapper for connection-drop and rollback cleanup.
pub(crate) async fn fenced_disconnect_with_retry(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
) -> Result<bool> {
    let _agent_guard = router
        .execution
        .external
        .agent_lock(project_id, agent_id)?
        .lock_owned()
        .await;
    fenced_disconnect_locked_with_retry(
        router,
        project_id,
        agent_id,
        session_id,
        lease_generation,
        reason,
    )
    .await
}

async fn fenced_disconnect_locked_with_retry(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
) -> Result<bool> {
    let mut last_err = None;
    for attempt in 0..3u64 {
        let deadline = crate::runtime::serve::options(std::time::Duration::from_secs(10))?;
        match fenced_disconnect_locked_on_execution(
            &router.execution,
            &router.context.owner,
            project_id,
            agent_id,
            session_id,
            lease_generation,
            reason,
            &deadline,
        )
        .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(err) => {
                last_err = Some(err);
                if attempt < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(50 * (attempt + 1))).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        SeError::invalid("external disconnect cleanup", "settled durable revocation")
    }))
}

#[allow(clippy::too_many_arguments)]
async fn fenced_disconnect_locked_on_execution(
    execution: &ExecutionContext,
    owner: &HumanId,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
    deadline: &Deadline,
) -> Result<bool> {
    let Some(lease) =
        execution
            .external
            .matching_lease(project_id, agent_id, session_id, lease_generation)?
    else {
        return Ok(false);
    };
    let rev_info = {
        let reads = execution.reads.clone();
        let generation = execution.generation;
        let owner = owner.clone();
        let project = project_id.clone();
        let target_session = session_id.clone();
        let target_cred = lease.credential_id;
        execution
            .blocking
            .run_owned(deadline, move || {
                let phase = reads.read_phase().map_err(|e| store_error(&e))?;
                let current_owner = phase.runtime_owner().map_err(|e| store_error(&e))?;
                if !matches!(current_owner, Read::Present { value } if value.generation == generation)
                {
                    return crate::runtime::executor::close_read(
                        Err(se_core::scope::unreadable(
                            "external disconnect generation",
                            "host generation changed",
                        )),
                        phase.close(),
                    );
                }
                let admission = Admission {
                    scope: Scope::Project(project),
                    actor: Actor::Human(owner),
                    session: None,
                    generation: generation.get(),
                };
                let mut snap = phase
                    .into_snapshot(se_core::admission::read_scope(&admission))
                    .map_err(|e| store_error(&e))?;
                let res = (|| {
                    let Read::Present { value: session_rec } = snap
                        .session(target_session)
                        .map_err(|e| store_error(&e))?
                    else {
                        return Ok(None);
                    };
                    if !matches!(
                        session_rec.current.body,
                        EventBody::SessionPrepared { .. } | EventBody::SessionActivated { .. }
                    ) {
                        return Ok(None);
                    }
                    Ok(Some((session_rec.revision, target_cred, commit::rev(2))))
                })();
                crate::runtime::executor::close_read(res, snap.close())
            })
            .await?
    };
    let Some((session_rev, cred_id, cred_rev)) = rev_info else {
        let _ = execution.external.remove_if_matching(
            project_id,
            agent_id,
            session_id,
            lease_generation,
        )?;
        return Ok(false);
    };
    let observer_warning = commit::commit_revocation_on_execution(
        execution,
        owner,
        project_id,
        session_id,
        session_rev,
        Some((cred_id, cred_rev)),
        reason,
        deadline,
    )
    .await?;
    let _ = execution.external.remove_if_matching(
        project_id,
        agent_id,
        session_id,
        lease_generation,
    )?;
    if let Some(warn) = observer_warning {
        return Err(warn);
    }
    Ok(true)
}
