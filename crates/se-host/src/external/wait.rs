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
    after: Option<se_types::Cursor>,
    timeout_ms: u64,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<ExternalMailWaitOutput> {
    router.check_open()?;
    let bounded_ms = timeout_ms.clamp(1, MAX_WAIT_TIMEOUT_MS);
    let stage = Duration::from_millis(bounded_ms.saturating_add(5_000));
    let deadline = crate::runtime::serve::options(stage)?;
    let until = tokio::time::Instant::now() + Duration::from_millis(bounded_ms);

    let first = read_page(router, &principal, &deadline, after.as_ref()).await?;
    let pins = Pins {
        session: first.session.clone(),
        recipient: first.recipient.clone(),
        credential: first.credential,
    };
    // Register BEFORE the deciding read so no commit can fall between snapshot
    // and waiter installation.
    let wait = router.execution.mail_waits.register(
        pins.session.clone(),
        pins.recipient.clone(),
        pins.credential,
    )?;
    // External seats may report turns; managed seats' turns are observed elsewhere.
    let mut activity = external_lease(router, &principal, &first)?
        .map(|lease| activity::Watch::new(&lease.activity));
    let after = after.as_ref();

    loop {
        if wait.signal.cancelled.load(Ordering::Acquire) {
            return Err(seat_closed());
        }
        let (page, gate) =
            decide(router, &principal, &deadline, &pins, &mut activity, after).await?;
        if gate == activity::Gate::Return {
            return Ok(output(page, "messages", None));
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                return Err(SeError::invalid("mail wait", "host is shutting down"));
            }
            _ = wait.signal.changed.notified() => {
                continue;
            }
            // A change, or a dropped state when the lease retired: `decide`
            // re-reads and re-resolves the lease either way.
            _ = async {
                match activity.as_mut() {
                    Some(watch) => watch.changed().await,
                    None => std::future::pending().await,
                }
            } => continue,
            _ = tokio::time::sleep_until(until) => {
                // Recheck authority and final inbox state on timeout; never mark read.
                let (page, gate) =
                    decide(router, &principal, &deadline, &pins, &mut activity, after).await?;
                return Ok(match gate {
                    activity::Gate::Return => output(page, "messages", None),
                    // Held mail stays listed, but a busy reply returns the
                    // caller's exact cursor, so passing it back hides nothing.
                    // Without one it carries the live cursor; the finished turn
                    // still returns all unread mail regardless of `after`.
                    activity::Gate::Busy => output(page, "busy", after),
                    activity::Gate::Hold => output(page, "empty", None),
                });
            }
        }
    }
}

struct Pins {
    session: SessionId,
    recipient: crate::runtime::MailRecipient,
    credential: se_store::RecordId,
}

/// A runner reporting turns faster than a wait can decide is not making progress.
const DECISION_ATTEMPTS: usize = 16;

/// Observe the seat's turn state, then read the inbox, then decide. A state
/// change in between means the page may predate it, so observe and read again.
async fn decide(
    router: &HostedRouter,
    principal: &WaitPrincipal,
    deadline: &Deadline,
    pins: &Pins,
    activity: &mut Option<activity::Watch>,
    after: Option<&se_types::Cursor>,
) -> Result<(crate::http::mail::Page, activity::Gate)> {
    for _ in 0..DECISION_ATTEMPTS {
        let seen = activity.as_mut().map(activity::Watch::observe);
        let page = read_page(router, principal, deadline, after).await?;
        verify_same_binding(&page, &pins.session, &pins.recipient, pins.credential)?;
        if activity.as_ref().is_some_and(activity::Watch::retired) {
            // The observed lease retired around the read: decide only from the
            // current authoritative lease, or refuse when there is none.
            let lease = external_lease(router, principal, &page)?.ok_or_else(seat_closed)?;
            *activity = Some(activity::Watch::new(&lease.activity));
            continue;
        }
        let has_ids = !page.ids.is_empty();
        let fresh = after.map(se_types::Cursor::as_str) != Some(page.cursor.as_str());
        let gate = match (activity.as_mut(), seen) {
            (Some(watch), Some(seen)) => match watch.decide(seen, has_ids, fresh) {
                Some(gate) => gate,
                None => continue,
            },
            _ => activity::untracked(has_ids, fresh),
        };
        return Ok((page, gate));
    }
    Err(SeError::invalid(
        "mail wait",
        "a seat whose runner reports each turn once; its busy and idle reports changed on every read. Report busy when a turn starts and idle when it ends, then wait again",
    ))
}

fn output(
    page: crate::http::mail::Page,
    status: &str,
    cursor: Option<&se_types::Cursor>,
) -> ExternalMailWaitOutput {
    ExternalMailWaitOutput {
        status: status.into(),
        session_id: page.session,
        ids: page.ids,
        cursor: cursor.cloned().unwrap_or(page.cursor),
        complete: page.complete,
    }
}

/// The external lease behind this wait, if its principal is an external seat.
fn external_lease(
    router: &HostedRouter,
    principal: &WaitPrincipal,
    page: &crate::http::mail::Page,
) -> Result<Option<ActiveLease>> {
    let now_us = crate::runtime::start::now_unix_micros()?;
    let external = &router.execution.external;
    match principal {
        WaitPrincipal::Credential { purpose, .. } if *purpose == EXTERNAL_SESSION_CAPABILITY => {
            Ok(external
                .active_lease(&page.recipient.project, &page.recipient.agent, now_us)?
                .filter(|lease| lease.session_id == page.session))
        }
        WaitPrincipal::Credential { .. } => Ok(None),
        WaitPrincipal::OwnerForExternal {
            project,
            agent,
            session_id,
            lease_generation,
            ..
        } => external.matching_active_lease(project, agent, session_id, *lease_generation, now_us),
    }
}

fn seat_closed() -> SeError {
    SeError::invalid(
        "mail wait",
        "this seat's active session was revoked, replaced, or disconnected",
    )
}

fn verify_same_binding(
    page: &crate::http::mail::Page,
    session: &SessionId,
    recipient: &crate::runtime::MailRecipient,
    credential: se_store::RecordId,
) -> Result<()> {
    if page.session != *session || page.recipient != *recipient || page.credential != credential {
        return Err(seat_closed());
    }
    Ok(())
}

async fn read_page(
    router: &HostedRouter,
    principal: &WaitPrincipal,
    deadline: &Deadline,
    after: Option<&se_types::Cursor>,
) -> Result<crate::http::mail::Page> {
    let after = after.cloned();
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
                    context.mail_page_for_purpose(&secret, purpose, after.as_ref())
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
                        after.as_ref(),
                    )
                })
                .await
        }
    }
}
