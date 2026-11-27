//! Separate authenticated blocking mail wait channel for external and managed seats.
//! Reuses `execution.mail_waits` with zero inbox polling while parked, registers
//! before the deciding read, wakes on unread/commit/revocation/disconnect/timeout,
//! and never marks messages read or delivered.
use super::*;
use crate::{HostedRouter, client::lease::Deadline};
use se_types::{Result, SeError, Secret};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::sync::watch;

/// Who is waiting on mail. Never parks an MCP tool call on the stdio pipe.
pub(crate) enum WaitPrincipal {
    /// Authenticated by a session or external-session capability secret.
    Credential {
        secret: Arc<Secret>,
        purpose: &'static str,
    },
    /// Authenticated by OwnerProof pinned to one exact external seat lease.
    OwnerForExternal {
        project: ProjectId,
        agent: AgentId,
        session_id: SessionId,
        credential_id: se_store::RecordId,
        lease_generation: u64,
    },
}

pub(crate) async fn wait_mail(
    router: &HostedRouter,
    principal: WaitPrincipal,
    after: Option<String>,
    timeout_ms: u64,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<ExternalMailWaitOutput> {
    router.check_open()?;
    let bounded_ms = timeout_ms.clamp(1, MAX_WAIT_TIMEOUT_MS);
    let stage = Duration::from_millis(bounded_ms.saturating_add(5_000));
    let deadline = crate::runtime::serve::options(stage)?;
    let until = tokio::time::Instant::now() + Duration::from_millis(bounded_ms);

    let first = read_page(router, &principal, &deadline).await?;
    let pinned_session = first.session.clone();
    let pinned_recipient = first.recipient.clone();
    let pinned_credential = first.credential;
    // Register BEFORE the deciding read so no commit can fall between snapshot
    // and waiter installation.
    let wait = router.execution.mail_waits.register(
        pinned_session.clone(),
        pinned_recipient.clone(),
        pinned_credential,
    )?;

    loop {
        if wait.signal.cancelled.load(Ordering::Acquire) {
            return Err(SeError::invalid(
                "mail wait",
                "this seat's active session was revoked, replaced, or disconnected",
            ));
        }
        let page = read_page(router, &principal, &deadline).await?;
        verify_same_binding(&page, &pinned_session, &pinned_recipient, pinned_credential)?;
        if !page.ids.is_empty() && after.as_deref() != Some(page.cursor.as_str()) {
            return Ok(ExternalMailWaitOutput {
                status: "messages".into(),
                session_id: page.session,
                ids: page.ids,
                cursor: page.cursor,
                complete: page.complete,
            });
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                return Err(SeError::invalid("mail wait", "host is shutting down"));
            }
            _ = wait.signal.changed.notified() => {
                continue;
            }
            _ = tokio::time::sleep_until(until) => {
                // Recheck authority and final inbox state on timeout; never mark read.
                let final_page = read_page(router, &principal, &deadline).await?;
                verify_same_binding(
                    &final_page,
                    &pinned_session,
                    &pinned_recipient,
                    pinned_credential,
                )?;
                let status = if !final_page.ids.is_empty()
                    && after.as_deref() != Some(final_page.cursor.as_str())
                {
                    "messages"
                } else {
                    "empty"
                };
                return Ok(ExternalMailWaitOutput {
                    status: status.into(),
                    session_id: final_page.session,
                    ids: final_page.ids,
                    cursor: final_page.cursor,
                    complete: final_page.complete,
                });
            }
        }
    }
}

fn verify_same_binding(
    page: &crate::http::mail::Page,
    session: &SessionId,
    recipient: &crate::runtime::MailRecipient,
    credential: se_store::RecordId,
) -> Result<()> {
    if page.session != *session || page.recipient != *recipient || page.credential != credential {
        return Err(SeError::invalid(
            "mail wait",
            "this seat's active session was revoked, replaced, or disconnected",
        ));
    }
    Ok(())
}

async fn read_page(
    router: &HostedRouter,
    principal: &WaitPrincipal,
    deadline: &Deadline,
) -> Result<crate::http::mail::Page> {
    router.check_open()?;
    let context = router.context.clone();
    match principal {
        WaitPrincipal::Credential { secret, purpose } => {
            let secret = Arc::clone(secret);
            let purpose = *purpose;
            router
                .execution
                .blocking
                .run_owned(deadline, move || {
                    context.mail_page_for_purpose(&secret, purpose)
                })
                .await
        }
        WaitPrincipal::OwnerForExternal {
            project,
            agent,
            session_id,
            credential_id,
            lease_generation,
        } => {
            let now_us = crate::runtime::start::now_unix_micros()?;
            if router
                .execution
                .external
                .matching_active_lease(project, agent, session_id, *lease_generation, now_us)?
                .is_none()
            {
                let _ = lifecycle::reconcile_expired_leases(router, Some(project)).await;
                return Err(SeError::invalid(
                    "external mail wait",
                    "this seat's active session was revoked, replaced, expired, or disconnected",
                ));
            }
            let project = project.clone();
            let agent = agent.clone();
            let session_id = session_id.clone();
            let credential_id = *credential_id;
            router
                .execution
                .blocking
                .run_owned(deadline, move || {
                    context.mail_page_for_active_external(
                        &project,
                        &agent,
                        &session_id,
                        credential_id,
                    )
                })
                .await
        }
    }
}
