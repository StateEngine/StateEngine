//! One atomic replacement of both transport grants for a native restart.
use super::*;
use se_types::StartIdentity;

fn order(value: &StartIdentity) -> (u8, u64, u32) {
    match value {
        StartIdentity::Linux { start_ticks } => (1, *start_ticks, 0),
        StartIdentity::Windows { creation_filetime } => (2, creation_filetime.get(), 0),
        StartIdentity::Macos {
            start_seconds,
            start_micros,
        } => (3, *start_seconds, *start_micros),
    }
}

/// Facts are supplied by the host's native peer observer, never the wire.
pub struct RebindGrant {
    pub session: se_types::SessionId,
    pub agent: se_types::AgentId,
    pub restart: se_store::CredentialRestart,
    pub key: IdempotencyKey,
    pub session_hash: [u8; 32],
    pub http_hash: [u8; 32],
}

pub fn rebind<R: Snapshot>(
    kernel: &Kernel,
    request: RebindGrant,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let session = scope::require_present(
        cx.read
            .session(request.session.clone())
            .map_err(|error| crate::store_error::store_error(&error))?,
        "rebind session",
        "Restore the original active session before retrying.",
    )?;
    let original = session.original.as_deref().unwrap_or(&session.current);
    if !matches!(&session.current.body, EventBody::SessionActivated { .. })
        || !matches!(&original.body, EventBody::SessionPrepared { agent, provider: se_store::Provider::SeCode, .. } if agent == &request.agent)
    {
        return Err(scope::unreadable(
            "rebind session",
            "the registered SE Code session is no longer active; restore the original session before retrying",
        ));
    }
    let mut heads = Vec::new();
    for purpose in ["session", "http"] {
        let id = session_credential_id(&request.session, purpose)?;
        let head = scope::require_present(
            cx.read
                .credential_head(id)
                .map_err(|error| crate::store_error::store_error(&error))?,
            "rebind credential",
            "Restore both original active credentials before retrying.",
        )?;
        if head.record.session != request.session
            || head.record.agent != request.agent
            || head.record.purpose != purpose
            || head.record.state != se_store::CredentialState::Active
        {
            return Err(scope::unreadable(
                "rebind credential",
                "the original active grant differs; restore its session before retrying",
            ));
        }
        heads.push((id, head));
    }
    if heads[0].1.restart != heads[1].1.restart {
        return Err(scope::unreadable(
            "rebind credential",
            "the two credential heads do not share a restart; preserve the original session for repair",
        ));
    }
    if let Some(previous) = &heads[0].1.restart
        && previous.boot == request.restart.boot
    {
        let old = order(&previous.started);
        let new = order(&request.restart.started);
        if old.0 != new.0 || new < old || (new == old && previous != &request.restart) {
            return Err(scope::unreadable(
                "rebind restart",
                "this process is older than or ambiguous with the current grant; use the newest registered service",
            ));
        }
    }
    let expires = kernel
        .facts()?
        .occurred_at_us
        .checked_add(86_400_000_000)
        .ok_or_else(|| scope::unreadable("rebind expiry", "clock overflow"))?;
    let intent = serde_json::json!({"session":request.session, "agent":request.agent, "restart":request.restart,
        "session_hash":request.session_hash, "http_hash":request.http_hash});
    let bodies = heads
        .into_iter()
        .zip([request.session_hash, request.http_hash])
        .map(|((credential, head), hash)| EventBody::CredentialRotated {
            credential,
            session: request.session.clone(),
            secret_sha256: hash,
            expires_at_us: expires,
            restart: request.restart.clone(),
            expected: Expected::Revision(head.record.revision),
        })
        .collect();
    batch(kernel, "session.rebind", request.key, intent, bodies, cx)
}
