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

/// Atomically mark the bridge closed, take any bound active seat, cancel any
/// pending claim, and durably revoke any seat owned by this connection.
async fn close_bridge_and_revoke(
    router: &HostedRouter,
    claim_id: Option<&str>,
    active_binding: &Arc<Mutex<ActiveConnectionBinding>>,
    reason: &str,
) {
    let active = active_binding.lock().ok().and_then(|mut b| {
        b.closed = true;
        b.active.take()
    });
    let undelivered = claim_id.and_then(|id| router.execution.external.cancel_pending_claim(id));
    if let Some((project_id, agent_id, session_id, lease_generation)) = &active {
        let _ = lifecycle::fenced_disconnect_with_retry(
            router,
            project_id,
            agent_id,
            session_id,
            *lease_generation,
            reason,
        )
        .await;
    }
    if let Some(undelivered) = undelivered
        && active.as_ref().is_none_or(|(_, _, s, g)| {
            *s != undelivered.session_id || *g != undelivered.lease_generation
        })
    {
        let _ = lifecycle::fenced_disconnect_with_retry(
            router,
            &undelivered.project_id,
            &undelivered.agent_id,
            &undelivered.session_id,
            undelivered.lease_generation,
            reason,
        )
        .await;
    }
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
