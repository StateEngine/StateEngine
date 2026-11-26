//! Atomic host-writer lifecycle operations for external seats: approve, revoke,
//! expiry reconciliation, and lease-generation-fenced disconnect cleanup.
use super::{commit, *};
use crate::{
    HostedRouter,
    client::lease::Deadline,
    runtime::{WriteIdentity, start::now_unix_micros, submit},
};
use se_core::store_error::store_error;
use se_store::{Actor, Admission, EventBody, Scope, Snapshot};
use se_types::{AgentId, ProjectId, Read, Result, SeError, Secret, SessionId};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const EXPIRED_LEASE_REASON: &str = "external seat lease expired";

/// Resolve an agent selector (exact ID or display name) and verify external eligibility.
pub(crate) fn resolve_external_agent(
    phase: se_store::ReadPhase,
    project: &ProjectId,
    owner: &se_types::HumanId,
    generation: u64,
    selector: &str,
    require_external: bool,
) -> Result<(AgentId, String, se_store::Provider)> {
    let admission = Admission {
        scope: Scope::Project(project.clone()),
        actor: Actor::Human(owner.clone()),
        session: None,
        generation,
    };
    let mut snapshot = phase
        .into_snapshot(se_core::admission::read_scope(&admission))
        .map_err(|e| store_error(&e))?;
    let result = (|| {
        let mut after = None;
        for _ in 0..64 {
            let page = snapshot
                .active_principals(crate::read_budget(
                    after,
                    100,
                    1024 * 1024,
                    std::time::Duration::from_secs(1),
                ))
                .map_err(|e| store_error(&e))?;
            let next = page.next().cloned();
            let complete = page.window().complete();
            for record in page.into_items() {
                let (agent_id, name) = match &record.current.body {
                    EventBody::PrincipalRegistered {
                        principal: Actor::Agent(id),
                        name,
                        ..
                    }
                    | EventBody::PrincipalRenamed {
                        principal: Actor::Agent(id),
                        name,
                        ..
                    } => (id.clone(), name.clone()),
                    _ => continue,
                };
                if agent_id.as_str() == selector || name == selector {
                    let profile_rec = se_core::scope::require_present(
                        snapshot
                            .profile(agent_id.clone())
                            .map_err(|e| store_error(&e))?,
                        "external agent profile",
                        "Save a valid agent profile before joining an external seat.",
                    )?;
                    let EventBody::ProfileSaved { profile, .. } = profile_rec.current.body else {
                        return Err(se_core::scope::unreadable(
                            "external agent profile",
                            "unexpected profile event kind",
                        ));
                    };
                    if require_external && !profile.external {
                        return Err(SeError::invalid(
                            "external seat agent",
                            "an agent marked external-eligible (`se agent add <name> --external`)",
                        ));
                    }
                    return Ok((agent_id, name, profile.provider));
                }
            }
            match next {
                Some(cursor) => after = Some(cursor),
                None if complete => {
                    return Err(SeError::invalid(
                        "external seat agent",
                        "an existing active agent in this project",
                    ));
                }
                None => break,
            }
        }
        Err(se_core::scope::unreadable(
            "external seat agent",
            "agent inventory is incomplete",
        ))
    })();
    let closed = snapshot.close();
    crate::runtime::executor::close_read(result, closed)
}

/// Durably revoke any expired external leases still tracked in this host's registry.
pub(crate) async fn reconcile_expired_leases(
    router: &HostedRouter,
    project: Option<&ProjectId>,
) -> Result<usize> {
    let now_us = now_unix_micros()?;
    let expired = router.execution.external.expired_leases(project, now_us)?;
    let mut reconciled = 0usize;
    for lease in expired {
        if fenced_disconnect(
            router,
            &lease.project_id,
            &lease.agent_id,
            &lease.session_id,
            lease.lease_generation,
            EXPIRED_LEASE_REASON,
        )
        .await
        .unwrap_or(false)
        {
            reconciled += 1;
        }
    }
    Ok(reconciled)
}

/// Owner approves a pending claim once. Atomically commits the external session
/// and credential in the host writer (arbitrated by per-agent exclusivity),
/// then delivers the capability exclusively to the waiting bridge connection.
pub(crate) async fn approve_claim(
    router: &HostedRouter,
    claim_id: &str,
    deadline: &Deadline,
) -> Result<ExternalApproveOutput> {
    router.check_open()?;
    let host_generation = router.context.generation;
    // Peek BEFORE consuming so a live-seat refusal leaves the pending claim intact.
    let peeked = router
        .execution
        .external
        .peek_claim(claim_id, host_generation)?;
    let _ = reconcile_expired_leases(router, Some(&peeked.project_id)).await;
    // Check for an existing live session or crash-recovered stale external session
    // before consuming the claim.
    let live_check = {
        let context = router.context.clone();
        let project_id = peeked.project_id.clone();
        let agent_id = peeked.agent_id.clone();
        router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
                if let Err(error) = context.check_generation(&phase) {
                    return crate::runtime::executor::close_read(Err(error), phase.close());
                }
                commit::inspect_live_seat(
                    phase,
                    &project_id,
                    &context.owner,
                    context.generation.get(),
                    &agent_id,
                )
            })
            .await?
    };
    match live_check {
        commit::LiveSeatCheck::Clear => {}
        commit::LiveSeatCheck::StaleExternal(stale, reason) => {
            commit::commit_revocation(
                router,
                &peeked.project_id,
                &stale.session_id,
                stale.session_rev,
                stale.cred,
                reason,
                deadline,
            )
            .await?;
        }
        commit::LiveSeatCheck::LiveConflict(remedy) => {
            return Err(SeError::invalid("external seat approval", remedy));
        }
    }
    let consumed = router
        .execution
        .external
        .consume_claim(claim_id, host_generation)?;
    let lease_generation = router.execution.external.allocate_lease_generation();
    let now_us = now_unix_micros()?;
    let expires_at_us = now_us
        .checked_add((EXTERNAL_LEASE_TTL_SECS as i64) * 1_000_000)
        .ok_or_else(|| SeError::invalid("external lease expiry", "clock overflow"))?;

    // Mint fresh in-memory capability bytes (never persisted in plaintext).
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
    submit::submit(&router.execution, batch, &identity, deadline).await?;

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
    };
    router.execution.external.record_active_lease(active)?;

    // Deliver the capability exclusively to the waiting bridge connection.
    // If the bridge disconnected before delivery, immediately revoke the just-minted seat.
    let delivered = consumed
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
        let _ = fenced_disconnect_with_retry(
            router,
            &consumed.project_id,
            &consumed.agent_id,
            &session_id,
            lease_generation,
            "external bridge disconnected before capability delivery",
        )
        .await;
        return Err(SeError::invalid(
            "external claim approval",
            "a still-connected bridge waiting on this claim; the bridge disconnected so the seat was revoked",
        ));
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

/// Owner revokes an active external seat by agent name or ID.
pub(crate) async fn revoke_seat(
    router: &HostedRouter,
    project: ProjectId,
    agent_selector: &str,
    reason: &str,
    deadline: &Deadline,
) -> Result<ExternalRevokeOutput> {
    router.check_open()?;
    let (agent_id, active) = {
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
                let phase2 = context.reads.read_phase().map_err(|e| store_error(&e))?;
                let active = commit::find_active_external_session(
                    phase2,
                    &project,
                    &context.owner,
                    context.generation.get(),
                    &agent_id,
                )?;
                Ok((agent_id, active))
            })
            .await?
    };

    // Commit durable revocation BEFORE mutating in-memory registry state, and
    // fence removal by exact `(session_id, lease_generation)` so a newer
    // replacement lease can never be wiped.
    commit::commit_revocation(
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

/// Bounded retry wrapper for connection-drop and rollback cleanup so transient
/// writer errors do not silently strand an active external session.
pub(crate) async fn fenced_disconnect_with_retry(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
) -> Result<bool> {
    let mut last_err = None;
    for attempt in 0..3u64 {
        match fenced_disconnect(
            router,
            project_id,
            agent_id,
            session_id,
            lease_generation,
            reason,
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

/// Lease-generation-fenced disconnect cleanup. A delayed close from an old
/// connection can NEVER revoke a successor lease, and the in-memory lease entry
/// is retained until the durable writer outcome settles.
pub(crate) async fn fenced_disconnect(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
) -> Result<bool> {
    let Some(lease) = router.execution.external.matching_lease(
        project_id,
        agent_id,
        session_id,
        lease_generation,
    )?
    else {
        // Already superseded by a newer lease or already revoked by Owner.
        return Ok(false);
    };
    let deadline = crate::runtime::serve::options(std::time::Duration::from_secs(10))?;
    let rev_info = {
        let context = router.context.clone();
        let project = project_id.clone();
        let target_session = session_id.clone();
        let target_cred = lease.credential_id;
        router
            .execution
            .blocking
            .run_owned(&deadline, move || {
                let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
                if let Err(error) = context.check_generation(&phase) {
                    return crate::runtime::executor::close_read(Err(error), phase.close());
                }
                let admission = Admission {
                    scope: Scope::Project(project.clone()),
                    actor: Actor::Human(context.owner.clone()),
                    session: None,
                    generation: context.generation.get(),
                };
                let mut snap = phase
                    .into_snapshot(se_core::admission::read_scope(&admission))
                    .map_err(|e| store_error(&e))?;
                let res = (|| {
                    let Read::Present { value: session_rec } = snap
                        .session(target_session.clone())
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
        // Durable state is already settled (revoked/ended/absent); safe to clear registry entry.
        let _ = router.execution.external.remove_if_matching(
            project_id,
            agent_id,
            session_id,
            lease_generation,
        )?;
        return Ok(false);
    };
    commit::commit_revocation(
        router,
        project_id,
        session_id,
        session_rev,
        Some((cred_id, cred_rev)),
        reason,
        &deadline,
    )
    .await?;
    let _ = router.execution.external.remove_if_matching(
        project_id,
        agent_id,
        session_id,
        lease_generation,
    )?;
    Ok(true)
}
