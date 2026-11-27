//! Atomic host-writer Owner RPC lifecycle operations for external seats:
//! approve and revoke (reconciliation and disconnect cleanup live in `reconcile`).
use super::{commit, reconcile, *};
use crate::{
    HostedRouter,
    client::lease::Deadline,
    runtime::{WriteIdentity, start::now_unix_micros, submit},
};
use se_core::store_error::store_error;
use se_types::{AgentId, ProjectId, Result, SeError, Secret, SessionId};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) use commit::resolve_external_agent;
pub(crate) use reconcile::{
    EXPIRED_LEASE_REASON, fenced_disconnect_with_retry, reconcile_expired_leases,
    reconcile_expired_on_execution, reconcile_external_for_launch_on_store,
};

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
            let outcome = reconcile::fenced_disconnect_locked_on_execution(
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
            if let Some(warn) = outcome.observer_warning {
                return Err(warn);
            }
        }
    }
    reconcile::reconcile_pending_revocations_on_execution(
        &router.execution,
        &router.context.owner,
        project_id,
        agent_id,
        deadline,
    )
    .await?;
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
            let revoke_identity = router.execution.external.ensure_revoke_identity(
                project_id,
                agent_id,
                &stale.session_id,
            )?;
            let warn = commit::commit_revocation(
                router,
                project_id,
                &stale.session_id,
                stale.session_rev,
                stale.cred,
                reason,
                revoke_identity,
                deadline,
            )
            .await?;
            let _ = router.execution.external.remove_if_session_and_retire(
                &router.execution.pending_writes,
                project_id,
                agent_id,
                &stale.session_id,
            )?;
            if let Some(warn) = warn {
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
        pending_write: None,
        approval_observer_lost: false,
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
        submit::RetainedCommit::ObserverLost(err) => {
            let mut pending = active.clone();
            pending.reconcile_required = true;
            pending.pending_write = Some(identity.clone());
            pending.approval_observer_lost = true;
            let _ = router.execution.external.record_active_lease(pending);
            Err(err)
        }
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
                Ok(true) => {
                    router.execution.pending_writes.resolve(identity)?;
                    Ok(None)
                }
                Ok(false) => {
                    router.execution.pending_writes.resolve(identity)?;
                    Err(err)
                }
                Err(read_err) => {
                    let mut pending = active.clone();
                    pending.reconcile_required = true;
                    pending.pending_write = Some(identity.clone());
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
        match reconcile::fenced_disconnect_locked_with_retry(
            router,
            &consumed.project_id,
            &consumed.agent_id,
            &session_id,
            lease_generation,
            "external bridge disconnected before capability delivery",
        )
        .await
        {
            Ok(outcome) => {
                if let Ok(mut b) = consumed.bridge.lock()
                    && b.active
                        .as_ref()
                        .is_some_and(|(_, _, s, g)| *s == session_id && *g == lease_generation)
                {
                    b.active = None;
                }
                let refusal = SeError::invalid(
                    "external claim approval",
                    "a still-connected bridge waiting on this claim; the bridge disconnected so the seat was revoked",
                );
                return Err(match outcome.observer_warning {
                    Some(warn) => refusal.with_cause(warn),
                    None => refusal,
                });
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

async fn resolve_agent_id_for_revoke(
    router: &HostedRouter,
    project: &ProjectId,
    agent_selector: &str,
    deadline: &Deadline,
) -> Result<AgentId> {
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
        .await
}

async fn read_active_external_session(
    router: &HostedRouter,
    project: &ProjectId,
    agent_id: &AgentId,
    deadline: &Deadline,
) -> Result<Option<commit::ActiveExternalSession>> {
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
        .await
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
    let agent_id = resolve_agent_id_for_revoke(router, &project, agent_selector, deadline).await?;
    let _agent_guard = router
        .execution
        .external
        .agent_lock(&project, &agent_id)?
        .lock_owned()
        .await;
    reconcile::reconcile_pending_revocations_on_execution(
        &router.execution,
        &router.context.owner,
        &project,
        &agent_id,
        deadline,
    )
    .await?;
    let active_opt = read_active_external_session(router, &project, &agent_id, deadline).await?;
    let active = match active_opt {
        Some(active) => active,
        None => {
            if let Some((session_id, lease_generation)) = router
                .execution
                .external
                .take_settled_revocation(&project, &agent_id)?
            {
                return Ok(ExternalRevokeOutput {
                    project_id: project,
                    agent_id,
                    session_id,
                    lease_generation,
                    revoked: true,
                });
            }
            return Err(SeError::invalid(
                "external seat",
                "an active external seat for this agent",
            ));
        }
    };

    let revoke_identity = router.execution.external.ensure_revoke_identity(
        &project,
        &agent_id,
        &active.session_id,
    )?;
    let observer_warning = commit::commit_revocation(
        router,
        &project,
        &active.session_id,
        active.session_rev,
        active.cred,
        reason,
        revoke_identity,
        deadline,
    )
    .await?;

    let _ = router
        .execution
        .external
        .take_settled_revocation(&project, &agent_id)?;

    let removed = match active.lease_generation {
        Some(lease_gen) => router.execution.external.remove_if_matching_and_retire(
            &router.execution.pending_writes,
            &project,
            &agent_id,
            &active.session_id,
            lease_gen,
        )?,
        None => router.execution.external.remove_if_session_and_retire(
            &router.execution.pending_writes,
            &project,
            &agent_id,
            &active.session_id,
        )?,
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
