//! Durable reconciliation and fenced disconnect cleanup for external seats:
//! lease expiry, pending-revocation settlement, managed-launch preflight, and
//! lease-generation-fenced disconnect retries.
use super::{commit, *};
use crate::{
    HostedRouter,
    client::lease::Deadline,
    runtime::{ExecutionContext, start::now_unix_micros},
};
use se_core::store_error::store_error;
use se_store::{Actor, Admission, EventBody, RecordId, Revision, Scope, Snapshot};
use se_types::{AgentId, HumanId, ProjectId, Read, Result, SeError, SessionId};

pub(crate) const EXPIRED_LEASE_REASON: &str = "external seat lease expired";

/// Result of a fenced disconnect cleanup: preserves any post-commit observer
/// warning separately from pre-commit retryable errors so retries never erase it.
pub(crate) struct DisconnectOutcome {
    pub revoked: bool,
    pub observer_warning: Option<SeError>,
}

/// Settle any tracked pending revocation identities for `(project_id, agent_id)`:
/// when the exact revocation write receipt is durably present, retires the lease
/// and `PendingWrites` and records the verified outcome on `ExternalRegistry` so
/// a subsequent Owner `revoke_seat` can report it even after a read failure or
/// intervening managed launch. Also retires terminal-session entries whose
/// receipt did not commit without recording a verified revoke outcome.
pub(crate) async fn reconcile_pending_revocations_on_store(
    store: &crate::runtime::store::Store,
    external: &ExternalRegistry,
    owner: &HumanId,
    project_id: &ProjectId,
    agent_id: &AgentId,
    deadline: &Deadline,
) -> Result<()> {
    for rev in external.pending_revocations_for_agent(project_id, agent_id)? {
        let receipt_committed = match rev.identity.key.clone() {
            Some(key) => {
                commit::revocation_receipt_committed_on_store(
                    store,
                    owner,
                    project_id,
                    &rev.session_id,
                    key,
                    deadline,
                )
                .await?
            }
            None => false,
        };
        if receipt_committed {
            let _ = external.settle_pending_revocation(
                &store.pending,
                project_id,
                agent_id,
                &rev.session_id,
                true,
            )?;
        } else if !commit::session_is_active_on_store(
            store,
            owner,
            project_id,
            &rev.session_id,
            deadline,
        )
        .await?
        {
            let _ = external.settle_pending_revocation(
                &store.pending,
                project_id,
                agent_id,
                &rev.session_id,
                false,
            )?;
        }
    }
    Ok(())
}

pub(crate) async fn reconcile_pending_revocations_on_execution(
    execution: &ExecutionContext,
    owner: &HumanId,
    project_id: &ProjectId,
    agent_id: &AgentId,
    deadline: &Deadline,
) -> Result<()> {
    let store = crate::runtime::store::Store::for_execution(execution);
    reconcile_pending_revocations_on_store(
        &store,
        &execution.external,
        owner,
        project_id,
        agent_id,
        deadline,
    )
    .await
}

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
        reconcile_pending_revocations_on_execution(
            execution,
            owner,
            &lease.project_id,
            &lease.agent_id,
            deadline,
        )
        .await?;
        let outcome = fenced_disconnect_locked_on_execution(
            execution,
            owner,
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
        if outcome.revoked {
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
        let revoke_identity = external.ensure_revoke_identity(
            &lease.project_id,
            &lease.agent_id,
            &lease.session_id,
        )?;
        let warn = commit::commit_revocation_on_store(
            store,
            owner,
            &lease.project_id,
            &lease.session_id,
            session_rev,
            Some((lease.credential_id, commit::rev(2))),
            EXPIRED_LEASE_REASON,
            revoke_identity,
            deadline,
        )
        .await?;
        let _ = external.settle_pending_revocation(
            &store.pending,
            &lease.project_id,
            &lease.agent_id,
            &lease.session_id,
            false,
        )?;
        if let Some(err) = warn {
            return Err(err);
        }
        Ok(true)
    } else {
        if lease.approval_observer_lost {
            return Err(se_core::scope::unreadable(
                "external seat approval",
                "approval write has no writer settlement witness; run `se down` then `se up` to restart the host and clear the unsettled identity",
            ));
        }
        let _ = external.remove_if_matching_and_retire(
            &store.pending,
            &lease.project_id,
            &lease.agent_id,
            &lease.session_id,
            lease.lease_generation,
        )?;
        Ok(false)
    }
}

/// Reconcile any expired, pending-revocation, or stale-generation external seat
/// for one agent before a managed `se launch` evaluates whether live takeover is required.
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
    reconcile_pending_revocations_on_store(store, external, owner, project_id, agent_id, deadline)
        .await?;
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
        let revoke_identity =
            external.ensure_revoke_identity(project_id, agent_id, &stale.session_id)?;
        let warn = commit::commit_revocation_on_store(
            store,
            owner,
            project_id,
            &stale.session_id,
            stale.session_rev,
            stale.cred,
            reason,
            revoke_identity,
            deadline,
        )
        .await?;
        let _ = external.settle_pending_revocation(
            &store.pending,
            project_id,
            agent_id,
            &stale.session_id,
            false,
        )?;
        if let Some(err) = warn {
            return Err(err);
        }
        changed = true;
    }
    Ok(changed)
}

/// Bounded retry wrapper for connection-drop and rollback cleanup.
pub(crate) async fn fenced_disconnect_with_retry(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
) -> Result<DisconnectOutcome> {
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

pub(crate) async fn fenced_disconnect_locked_with_retry(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
) -> Result<DisconnectOutcome> {
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

async fn read_live_session_rev_on_execution(
    execution: &ExecutionContext,
    owner: &HumanId,
    project_id: &ProjectId,
    session_id: &SessionId,
    credential_id: RecordId,
    deadline: &Deadline,
) -> Result<Option<(Revision, RecordId, Revision)>> {
    let reads = execution.reads.clone();
    let generation = execution.generation;
    let owner = owner.clone();
    let project = project_id.clone();
    let target_session = session_id.clone();
    execution
        .blocking
        .run_owned(deadline, move || {
            let phase = reads.read_phase().map_err(|e| store_error(&e))?;
            let current_owner = phase.runtime_owner().map_err(|e| store_error(&e))?;
            if !matches!(
                current_owner,
                Read::Present { value } if value.generation == generation
            ) {
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
                let Read::Present { value: session_rec } =
                    snap.session(target_session).map_err(|e| store_error(&e))?
                else {
                    return Ok(None);
                };
                if !matches!(
                    session_rec.current.body,
                    EventBody::SessionPrepared { .. } | EventBody::SessionActivated { .. }
                ) {
                    return Ok(None);
                }
                Ok(Some((session_rec.revision, credential_id, commit::rev(2))))
            })();
            crate::runtime::executor::close_read(res, snap.close())
        })
        .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fenced_disconnect_locked_on_execution(
    execution: &ExecutionContext,
    owner: &HumanId,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
    deadline: &Deadline,
) -> Result<DisconnectOutcome> {
    let Some(lease) =
        execution
            .external
            .matching_lease(project_id, agent_id, session_id, lease_generation)?
    else {
        return Ok(DisconnectOutcome {
            revoked: false,
            observer_warning: None,
        });
    };
    let rev_info = read_live_session_rev_on_execution(
        execution,
        owner,
        project_id,
        session_id,
        lease.credential_id,
        deadline,
    )
    .await?;
    let Some((session_rev, cred_id, cred_rev)) = rev_info else {
        if lease.approval_observer_lost {
            return Err(se_core::scope::unreadable(
                "external seat approval",
                "approval write has no writer settlement witness; run `se down` then `se up` to restart the host and clear the unsettled identity",
            ));
        }
        let _ = execution.external.remove_if_matching_and_retire(
            &execution.pending_writes,
            project_id,
            agent_id,
            session_id,
            lease_generation,
        )?;
        return Ok(DisconnectOutcome {
            revoked: false,
            observer_warning: None,
        });
    };
    let revoke_identity = execution
        .external
        .ensure_revoke_identity(project_id, agent_id, session_id)?;
    let observer_warning = commit::commit_revocation_on_execution(
        execution,
        owner,
        project_id,
        session_id,
        session_rev,
        Some((cred_id, cred_rev)),
        reason,
        revoke_identity,
        deadline,
    )
    .await?;
    let _ = execution.external.settle_pending_revocation(
        &execution.pending_writes,
        project_id,
        agent_id,
        session_id,
        false,
    )?;
    Ok(DisconnectOutcome {
        revoked: true,
        observer_warning,
    })
}
