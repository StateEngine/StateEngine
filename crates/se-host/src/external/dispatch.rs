//! Async execution and connection-drop cleanup for admitted external seat calls.
use super::*;
use crate::{
    HostedRouter, OperationOutput,
    client::lease::Deadline,
    runtime::admission::external::{ActiveConnectionBinding, ExternalCall},
};
use se_types::{Result, SeError};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

pub(crate) async fn execute(
    router: &HostedRouter,
    call: ExternalCall,
    active_binding: &Arc<Mutex<ActiveConnectionBinding>>,
    deadline: &Deadline,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<OperationOutput> {
    match call {
        ExternalCall::ClaimOpen { handle } => encode(
            "se.external-claim-open/v1",
            &ExternalClaimOpenOutput {
                claim_id: handle.claim_id,
                project_id: handle.project_id,
                agent_id: handle.agent_id,
                agent_name: handle.agent_name,
                scope: EXTERNAL_SEAT_SCOPE.to_owned(),
                expires_at_us: handle.expires_at_us,
            },
        ),
        ExternalCall::ClaimWait {
            claim_id,
            peer_binding,
            connection_nonce,
        } => {
            execute_claim_wait(
                router,
                claim_id,
                peer_binding,
                connection_nonce,
                active_binding,
                shutdown,
            )
            .await
        }
        ExternalCall::List { project } => {
            lifecycle::reconcile_expired_leases(router, project.as_ref()).await?;
            let now_us = crate::runtime::start::now_unix_micros()?;
            let output = router.execution.external.list(project.as_ref(), now_us)?;
            encode("se.external-list/v1", &output)
        }
        ExternalCall::Approve { claim_id } => {
            let output = lifecycle::approve_claim(router, &claim_id, deadline).await?;
            encode("se.external-approve/v1", &output)
        }
        ExternalCall::Revoke { project, agent } => {
            let output = lifecycle::revoke_seat(
                router,
                project,
                &agent,
                "revoked by owner via `se external revoke`",
                deadline,
            )
            .await?;
            encode("se.external-revoke/v1", &output)
        }
        ExternalCall::MailWait {
            principal,
            after,
            timeout_ms,
        } => {
            let output = wait::wait_mail(router, principal, after, timeout_ms, shutdown).await?;
            encode("se.external-mail-wait/v1", &output)
        }
    }
}

async fn execute_claim_wait(
    router: &HostedRouter,
    claim_id: String,
    peer_binding: Vec<u8>,
    connection_nonce: [u8; 32],
    active_binding: &Arc<Mutex<ActiveConnectionBinding>>,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<OperationOutput> {
    let (rx, expires_at) = router.execution.external.attach_waiter(
        &claim_id,
        &peer_binding,
        &connection_nonce,
        router.context.generation,
    )?;
    let until = tokio::time::Instant::from_std(expires_at);
    let delivery = tokio::select! {
        biased;
        _ = shutdown.changed() => {
            close_bridge_and_revoke(router, Some(&claim_id), active_binding, "host is shutting down").await;
            return Err(SeError::invalid("external claim wait", "host is shutting down"));
        }
        _ = tokio::time::sleep_until(until) => {
            close_bridge_and_revoke(
                router,
                Some(&claim_id),
                active_binding,
                "external claim expired before bridge received capability",
            )
            .await;
            return Err(SeError::invalid(
                "external claim wait",
                "approval before claim expiry; reconnect to open a fresh claim",
            ));
        }
        res = rx => match res {
            Ok(delivery) => delivery,
            Err(_) => {
                close_bridge_and_revoke(
                    router,
                    Some(&claim_id),
                    active_binding,
                    "external claim closed before capability delivery",
                )
                .await;
                return Err(SeError::invalid(
                    "external claim wait",
                    "owner approval before the claim closed",
                ));
            }
        },
    };
    let capability = std::str::from_utf8(delivery.secret.expose())
        .map_err(|_| SeError::invalid("external capability", "UTF-8 token"))?
        .to_owned();
    encode(
        "se.external-claim-approved/v1",
        &ExternalClaimApproved {
            project_id: delivery.project_id,
            agent_id: delivery.agent_id,
            agent_name: delivery.agent_name,
            session_id: delivery.session_id,
            lease_generation: delivery.lease_generation,
            expires_at_us: delivery.expires_at_us,
            capability,
        },
    )
}

/// Atomically mark the bridge closed and spawn durable cleanup on a detached
/// host task so peer EOF cancelling `ClaimWait` can never drop the cleanup
/// before durable revocation settles. Cleanup ownership stays in `active_binding`
/// and `registry.active` until revocation succeeds.
async fn close_bridge_and_revoke(
    router: &HostedRouter,
    claim_id: Option<&str>,
    active_binding: &Arc<Mutex<ActiveConnectionBinding>>,
    reason: &str,
) {
    let active = active_binding.lock().ok().and_then(|mut b| {
        b.closed = true;
        b.active.clone()
    });
    let undelivered = claim_id.and_then(|id| router.execution.external.cancel_pending_claim(id));
    if active.is_none() && undelivered.is_none() {
        return;
    }
    let router = router.clone();
    let binding = Arc::clone(active_binding);
    let reason = reason.to_owned();
    let handle = tokio::spawn(async move {
        if let Some((project_id, agent_id, session_id, lease_generation)) = &active {
            match lifecycle::fenced_disconnect_with_retry(
                &router,
                project_id,
                agent_id,
                session_id,
                *lease_generation,
                &reason,
            )
            .await
            {
                Ok(outcome) => {
                    if let Ok(mut b) = binding.lock()
                        && b.active.as_ref().is_some_and(|(_, _, s, g)| {
                            *s == *session_id && *g == *lease_generation
                        })
                    {
                        b.active = None;
                    }
                    if let Some(warn) = outcome.observer_warning {
                        eprintln!(
                            "stateengine: external disconnect cleanup committed with observer warning: session={session_id} lease_generation={lease_generation} error={warn}"
                        );
                    }
                }
                Err(err) => {
                    eprintln!(
                        "stateengine: external disconnect cleanup failed; retaining lease for reconciliation: session={session_id} lease_generation={lease_generation} error={err}"
                    );
                    router.execution.external.mark_reconcile_required(
                        project_id,
                        agent_id,
                        session_id,
                        *lease_generation,
                    );
                }
            }
        }
        if let Some(undelivered) = undelivered
            && active.as_ref().is_none_or(|(_, _, s, g)| {
                *s != undelivered.session_id || *g != undelivered.lease_generation
            })
        {
            match lifecycle::fenced_disconnect_with_retry(
                &router,
                &undelivered.project_id,
                &undelivered.agent_id,
                &undelivered.session_id,
                undelivered.lease_generation,
                &reason,
            )
            .await
            {
                Ok(outcome) => {
                    if let Some(warn) = outcome.observer_warning {
                        eprintln!(
                            "stateengine: external undelivered-claim cleanup committed with observer warning: session={} lease_generation={} error={warn}",
                            undelivered.session_id, undelivered.lease_generation
                        );
                    }
                }
                Err(err) => {
                    eprintln!(
                        "stateengine: external undelivered-claim cleanup failed; retaining lease for reconciliation: session={} lease_generation={} error={err}",
                        undelivered.session_id, undelivered.lease_generation
                    );
                    router.execution.external.mark_reconcile_required(
                        &undelivered.project_id,
                        &undelivered.agent_id,
                        &undelivered.session_id,
                        undelivered.lease_generation,
                    );
                }
            }
        }
    });
    // Await the detached task; if the caller future is cancelled by peer EOF,
    // dropping `handle` detaches the task rather than cancelling cleanup.
    let _ = handle.await;
}

/// Clean up any pending claim or active external lease owned by a disconnecting bridge.
pub(crate) async fn release_connection(
    router: &HostedRouter,
    claim: Option<PendingClaimHandle>,
    active_binding: &Arc<Mutex<ActiveConnectionBinding>>,
) {
    close_bridge_and_revoke(
        router,
        claim.as_ref().map(|h| h.claim_id.as_str()),
        active_binding,
        "external bridge disconnected",
    )
    .await;
}

fn encode<T: serde::Serialize>(schema: &str, value: &T) -> Result<OperationOutput> {
    Ok(OperationOutput {
        schema: schema.to_owned(),
        value: serde_json::to_value(value)
            .map_err(|e| se_core::scope::unreadable("external seat output", &e.to_string()))?,
        window: None,
    })
}
