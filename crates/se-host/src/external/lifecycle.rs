//! Atomic host-writer lifecycle operations for external seats: approve, revoke,
//! and lease-generation-fenced disconnect cleanup.
use super::*;
use crate::{
    HostedRouter,
    client::lease::Deadline,
    runtime::{WriteIdentity, start::now_unix_micros, submit},
};
use se_core::store_error::store_error;
use se_store::{
    Actor, Admission, AtomicBatch, Consent, ContainmentFact, Door, EventBody, EventHeader,
    Expected, InputText, NewEvent, RecordId, RecordIdentity, RequestIdentity, Revision, Scope,
    SessionSurface, Snapshot,
};
use se_types::{
    AgentId, EventId, IdempotencyKey, ProjectId, Read, Result, SeError, Secret, SessionId,
};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU64, sync::Arc};

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

    let (batch, session_id, credential_id, key) = build_approve_batch(
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
    let delivered = consumed.delivery.is_some_and(|tx| {
        tx.send(ClaimApprovalDelivery {
            project_id: consumed.project_id.clone(),
            agent_id: consumed.agent_id.clone(),
            agent_name: consumed.agent_name.clone(),
            session_id: session_id.clone(),
            lease_generation,
            expires_at_us,
            secret,
        })
        .is_ok()
    });
    if !delivered {
        let _ = fenced_disconnect(
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

async fn build_approve_batch(
    router: &HostedRouter,
    consumed: &registry::ConsumedClaim,
    lease_generation: u64,
    now_us: i64,
    expires_at_us: i64,
    secret_sha256: [u8; 32],
    deadline: &Deadline,
) -> Result<(AtomicBatch, SessionId, RecordId, IdempotencyKey)> {
    let context = router.context.clone();
    let project_id = consumed.project_id.clone();
    let agent_id = consumed.agent_id.clone();
    let claim_id = consumed.claim_id.clone();
    router
        .execution
        .blocking
        .run_owned(deadline, move || {
            let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
            if let Err(error) = context.check_generation(&phase) {
                return crate::runtime::executor::close_read(Err(error), phase.close());
            }
            let (_, _, provider) = resolve_external_agent(
                phase,
                &project_id,
                &context.owner,
                context.generation.get(),
                agent_id.as_str(),
                true,
            )?;
            let info_phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
            let admission = Admission {
                scope: Scope::Project(project_id.clone()),
                actor: Actor::Human(context.owner.clone()),
                session: None,
                generation: context.generation.get(),
            };
            let snap = info_phase
                .into_snapshot(se_core::admission::read_scope(&admission))
                .map_err(|e| store_error(&e))?;
            let info = snap.info();
            let res = (|| {
                let session_id = allocate_session_id(now_us)?;
                let credential_id = external_credential_id(&session_id)?;
                let key = IdempotencyKey::new(format!("external-approve-{claim_id}"))?;
                let intent = serde_json::json!({
                    "claim_id": claim_id,
                    "agent": agent_id,
                    "session": session_id,
                    "lease_generation": lease_generation,
                });
                let intent_bytes = serde_json::to_vec(&intent)
                    .map_err(|_| SeError::invalid("external approve intent", "valid JSON"))?;
                let events = approve_events(
                    &admission,
                    &info.id,
                    &session_id,
                    credential_id,
                    &agent_id,
                    provider,
                    &claim_id,
                    lease_generation,
                    secret_sha256,
                    now_us,
                    expires_at_us,
                )?;
                let batch = AtomicBatch {
                    expected_incarnation: info.incarnation,
                    admission,
                    request: Some(RequestIdentity {
                        key: key.clone(),
                        intent: se_store::IntentDigest {
                            operation: "external.approve",
                            codec_version: 1,
                            sha256: Sha256::digest(&intent_bytes).into(),
                        },
                    }),
                    import_checkpoint: None,
                    events,
                };
                Ok((batch, session_id, credential_id, key))
            })();
            crate::runtime::executor::close_read(res, snap.close())
        })
        .await
}

#[allow(clippy::too_many_arguments)]
fn approve_events(
    admission: &Admission,
    origin: &se_types::StoreId,
    session_id: &SessionId,
    credential_id: RecordId,
    agent_id: &AgentId,
    provider: se_store::Provider,
    claim_id: &str,
    lease_generation: u64,
    secret_sha256: [u8; 32],
    now_us: i64,
    expires_at_us: i64,
) -> Result<Vec<NewEvent>> {
    let activation_deadline_us = now_us
        .checked_add(600_000_000)
        .ok_or_else(|| SeError::invalid("activation deadline", "clock overflow"))?;
    Ok(vec![
        make_event(
            admission,
            origin,
            now_us,
            EventBody::SessionPrepared {
                session: session_id.clone(),
                agent: agent_id.clone(),
                provider,
                surface: Some(SessionSurface::External),
                native_ref: format!("external:{claim_id}"),
                consent: Consent::Suppressed,
                generation: admission.generation,
                expected: Expected::Absent,
            },
        )?,
        make_event(
            admission,
            origin,
            now_us,
            EventBody::SessionActivated {
                session: session_id.clone(),
                expected: Expected::Revision(rev(1)),
                incumbent: None,
                process: None,
                containment: ContainmentFact::ExternalSeat {
                    lease_generation,
                    observed_at_us: now_us,
                },
                witnesses: Vec::new(),
            },
        )?,
        make_event(
            admission,
            origin,
            now_us,
            EventBody::CredentialIssued {
                credential: credential_id,
                session: session_id.clone(),
                purpose: EXTERNAL_SESSION_CAPABILITY.to_owned(),
                secret_sha256,
                expires_at_us,
                activation_deadline_us,
                expected: Expected::Absent,
            },
        )?,
        make_event(
            admission,
            origin,
            now_us,
            EventBody::CredentialActivated {
                credential: credential_id,
                session: session_id.clone(),
                first_request: None,
                expected: Expected::Revision(rev(1)),
            },
        )?,
    ])
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
    let (agent_id, session_id, session_rev, cred_id) = {
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
                let active = find_active_external_session(
                    phase2,
                    &project,
                    &context.owner,
                    context.generation.get(),
                    &agent_id,
                )?;
                Ok((agent_id, active.session_id, active.session_rev, active.cred))
            })
            .await?
    };

    let removed = router
        .execution
        .external
        .remove_active(&project, &agent_id)?;
    let lease_generation = removed.as_ref().map(|lease| lease.lease_generation);
    commit_revocation(
        router,
        &project,
        &session_id,
        session_rev,
        cred_id,
        None,
        reason,
        deadline,
    )
    .await?;

    Ok(ExternalRevokeOutput {
        project_id: project,
        agent_id,
        session_id,
        lease_generation,
        revoked: true,
    })
}

/// Lease-generation-fenced disconnect cleanup. A delayed close from an old
/// connection can NEVER revoke a successor lease.
pub(crate) async fn fenced_disconnect(
    router: &HostedRouter,
    project_id: &ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    lease_generation: u64,
    reason: &str,
) -> Result<bool> {
    let Some(lease) = router.execution.external.remove_if_matching(
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
                    Ok(Some((session_rec.revision, target_cred, rev(2))))
                })();
                crate::runtime::executor::close_read(res, snap.close())
            })
            .await?
    };
    let Some((session_rev, cred_id, cred_rev)) = rev_info else {
        return Ok(false);
    };
    commit_revocation(
        router,
        project_id,
        session_id,
        session_rev,
        Some((cred_id, cred_rev)),
        None,
        reason,
        &deadline,
    )
    .await?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn commit_revocation(
    router: &HostedRouter,
    project: &ProjectId,
    session_id: &SessionId,
    session_rev: Revision,
    cred: Option<(RecordId, Revision)>,
    extra_cred_rev: Option<Revision>,
    reason: &str,
    deadline: &Deadline,
) -> Result<()> {
    let _ = extra_cred_rev;
    let now_us = now_unix_micros()?;
    let (batch, key) = {
        let context = router.context.clone();
        let project = project.clone();
        let session_id = session_id.clone();
        let reason = reason.to_owned();
        router
            .execution
            .blocking
            .run_owned(deadline, move || {
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
                let snap = phase
                    .into_snapshot(se_core::admission::read_scope(&admission))
                    .map_err(|e| store_error(&e))?;
                let info = snap.info();
                let res = (|| {
                    let nonce = crate::client::auth::fresh_nonce()?;
                    let key = IdempotencyKey::new(format!(
                        "external-revoke-{}-{}",
                        session_id,
                        se_types::hex_lower(&nonce[..8])
                    ))?;
                    let intent = serde_json::json!({
                        "session": session_id,
                        "reason": reason,
                    });
                    let intent_bytes = serde_json::to_vec(&intent)
                        .map_err(|_| SeError::invalid("external revoke intent", "valid JSON"))?;
                    let mut events = Vec::new();
                    if let Some((cred_id, cred_rev)) = cred {
                        events.push(make_event(
                            &admission,
                            &info.id,
                            now_us,
                            EventBody::CredentialRevoked {
                                credential: cred_id,
                                expected: Expected::Revision(cred_rev),
                                reason: InputText::Inline(reason.clone()),
                            },
                        )?);
                    }
                    events.push(make_event(
                        &admission,
                        &info.id,
                        now_us,
                        EventBody::SessionRevoked {
                            session: session_id.clone(),
                            expected: Expected::Revision(session_rev),
                            reason: InputText::Inline(reason),
                        },
                    )?);
                    let batch = AtomicBatch {
                        expected_incarnation: info.incarnation,
                        admission,
                        request: Some(RequestIdentity {
                            key: key.clone(),
                            intent: se_store::IntentDigest {
                                operation: "external.revoke",
                                codec_version: 1,
                                sha256: Sha256::digest(&intent_bytes).into(),
                            },
                        }),
                        import_checkpoint: None,
                        events,
                    };
                    Ok((batch, key))
                })();
                crate::runtime::executor::close_read(res, snap.close())
            })
            .await?
    };

    let identity = WriteIdentity {
        operation: "external.revoke",
        key: Some(key),
        natural_key: None,
        natural_events: Vec::new(),
    };
    submit::submit(&router.execution, batch, &identity, deadline).await?;

    // Immediately wake any parked wait channel for this session/credential.
    let mut revocations = crate::runtime::mail::Revocations::default();
    revocations
        .sessions
        .push((project.clone(), session_id.clone()));
    if let Some((cred_id, _)) = cred {
        revocations.credentials.push((project.clone(), cred_id));
    }
    let _ = router.execution.mail_waits.revoked(&revocations);
    Ok(())
}

struct ActiveExternalSession {
    session_id: SessionId,
    session_rev: Revision,
    cred: Option<(RecordId, Revision)>,
}

fn find_active_external_session(
    phase: se_store::ReadPhase,
    project: &ProjectId,
    owner: &se_types::HumanId,
    generation: u64,
    agent_id: &AgentId,
) -> Result<ActiveExternalSession> {
    let admission = Admission {
        scope: Scope::Project(project.clone()),
        actor: Actor::Human(owner.clone()),
        session: None,
        generation,
    };
    let mut snap = phase
        .into_snapshot(se_core::admission::read_scope(&admission))
        .map_err(|e| store_error(&e))?;
    let res = (|| {
        let target = se_core::scope::require_present(
            snap.control_target(agent_id.clone())
                .map_err(|e| store_error(&e))?,
            "external revoke target",
            "Verify the agent exists in this project.",
        )?;
        for session_rec in &target.sessions {
            let orig = session_rec
                .original
                .as_deref()
                .unwrap_or(&session_rec.current);
            let is_external = matches!(
                orig.body,
                EventBody::SessionPrepared {
                    surface: Some(SessionSurface::External),
                    ..
                }
            );
            if !is_external {
                continue;
            }
            let session_id = match &session_rec.current.body {
                EventBody::SessionActivated { session, .. }
                | EventBody::SessionPrepared { session, .. } => session.clone(),
                _ => continue,
            };
            let cred_id = external_credential_id(&session_id)?;
            return Ok(ActiveExternalSession {
                session_id,
                session_rev: session_rec.revision,
                cred: Some((cred_id, rev(2))),
            });
        }
        Err(SeError::invalid(
            "external seat",
            "an active external seat for this agent",
        ))
    })();
    crate::runtime::executor::close_read(res, snap.close())
}

fn rev(v: u64) -> Revision {
    Revision {
        value: NonZeroU64::new(v).unwrap_or(NonZeroU64::MIN),
    }
}

fn allocate_session_id(now_us: i64) -> Result<SessionId> {
    let millis = u64::try_from(now_us.max(0) / 1000).unwrap_or(0);
    let nonce = crate::client::auth::fresh_nonce()?;
    let mut random = [0u8; 10];
    random.copy_from_slice(&nonce[..10]);
    SessionId::from_parts(millis, random)
}

fn external_credential_id(session: &SessionId) -> Result<RecordId> {
    let mut hasher = Sha256::new();
    hasher.update(b"se.external.credential.v1");
    hasher.update(session.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from_bytes(bytes).map_err(|e| store_error(&e))
}

fn allocate_event_id(now_us: i64) -> Result<EventId> {
    let millis = u64::try_from(now_us.max(0) / 1000).unwrap_or(0);
    let nonce = crate::client::auth::fresh_nonce()?;
    let mut random = [0u8; 10];
    random.copy_from_slice(&nonce[..10]);
    EventId::from_parts(millis, random)
}

fn make_event(
    admission: &Admission,
    origin: &se_types::StoreId,
    now_us: i64,
    body: EventBody<InputText>,
) -> Result<NewEvent> {
    Ok(NewEvent {
        header: EventHeader {
            event: allocate_event_id(now_us)?,
            scope: admission.scope.clone(),
            actor: admission.actor.clone(),
            session: admission.session.clone(),
            origin: origin.clone(),
            door: Door::Host,
            occurred_at_us: now_us,
            cause: None,
            supersedes: None,
        },
        body,
    })
}
