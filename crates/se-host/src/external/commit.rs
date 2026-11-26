//! Durable store batch builders and commit helpers for external seat approval
//! and revocation.
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
use se_types::{AgentId, EventId, IdempotencyKey, ProjectId, Result, SeError, SessionId};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

pub(crate) struct ActiveExternalSession {
    pub session_id: SessionId,
    pub session_rev: Revision,
    pub lease_generation: Option<u64>,
    pub cred: Option<(RecordId, Revision)>,
}

pub(crate) enum LiveSeatCheck {
    Clear,
    StaleExternal(ActiveExternalSession, &'static str),
    LiveConflict(&'static str),
}

pub(crate) fn inspect_live_seat(
    phase: se_store::ReadPhase,
    project: &ProjectId,
    owner: &se_types::HumanId,
    generation: u64,
    agent_id: &AgentId,
) -> Result<LiveSeatCheck> {
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
            "external seat target",
            "Verify the agent exists in this project.",
        )?;
        for session_rec in &target.sessions {
            let orig = session_rec
                .original
                .as_deref()
                .unwrap_or(&session_rec.current);
            let is_live = matches!(
                session_rec.current.body,
                EventBody::SessionPrepared { .. } | EventBody::SessionActivated { .. }
            );
            if !is_live {
                continue;
            }
            if let EventBody::SessionPrepared {
                surface: Some(SessionSurface::External),
                generation: sess_gen,
                ..
            } = &orig.body
            {
                if *sess_gen != generation {
                    let (session_id, lease_generation) = match &session_rec.current.body {
                        EventBody::SessionActivated {
                            session,
                            containment:
                                ContainmentFact::ExternalSeat {
                                    lease_generation, ..
                                },
                            ..
                        } => (session.clone(), Some(*lease_generation)),
                        EventBody::SessionActivated { session, .. }
                        | EventBody::SessionPrepared { session, .. } => (session.clone(), None),
                        _ => continue,
                    };
                    let cred_id = external_credential_id(&session_id)?;
                    return Ok(LiveSeatCheck::StaleExternal(
                        ActiveExternalSession {
                            session_id,
                            session_rev: session_rec.revision,
                            lease_generation,
                            cred: Some((cred_id, rev(2))),
                        },
                        "previous host generation exited",
                    ));
                }
                return Ok(LiveSeatCheck::LiveConflict(
                    "no active external seat for this agent; revoke the live seat first with `se external revoke <agent>`",
                ));
            }
            return Ok(LiveSeatCheck::LiveConflict(
                "no active managed session for this agent; stop it first with `se stop <agent>`",
            ));
        }
        Ok(LiveSeatCheck::Clear)
    })();
    crate::runtime::executor::close_read(res, snap.close())
}

pub(crate) async fn build_approve_batch(
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
            let (_, _, provider) = lifecycle::resolve_external_agent(
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

pub(crate) async fn session_is_active(
    execution: &crate::runtime::ExecutionContext,
    owner: &se_types::HumanId,
    project: &ProjectId,
    session_id: &SessionId,
    deadline: &Deadline,
) -> Result<bool> {
    let reads = execution.reads.clone();
    let generation = execution.generation;
    let project = project.clone();
    let owner = owner.clone();
    let target = session_id.clone();
    execution
        .blocking
        .run_owned(deadline, move || {
            let phase = reads.read_phase().map_err(|e| store_error(&e))?;
            let admission = Admission {
                scope: Scope::Project(project),
                actor: Actor::Human(owner),
                session: None,
                generation: generation.get(),
            };
            let mut snap = phase
                .into_snapshot(se_core::admission::read_scope(&admission))
                .map_err(|e| store_error(&e))?;
            let active = match snap.session(target).map_err(|e| store_error(&e)) {
                Ok(se_types::Read::Present { value }) => Ok(matches!(
                    value.current.body,
                    EventBody::SessionPrepared { .. } | EventBody::SessionActivated { .. }
                )),
                Ok(_) => Ok(false),
                Err(err) => Err(err),
            };
            crate::runtime::executor::close_read(active, snap.close())
        })
        .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_revocation(
    router: &HostedRouter,
    project: &ProjectId,
    session_id: &SessionId,
    session_rev: Revision,
    cred: Option<(RecordId, Revision)>,
    reason: &str,
    deadline: &Deadline,
) -> Result<()> {
    commit_revocation_on_execution(
        &router.execution,
        &router.context.owner,
        project,
        session_id,
        session_rev,
        cred,
        reason,
        deadline,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_revocation_on_store(
    store: &crate::runtime::store::Store,
    owner: &se_types::HumanId,
    project: &ProjectId,
    session_id: &SessionId,
    session_rev: Revision,
    cred: Option<(RecordId, Revision)>,
    reason: &str,
    deadline: &Deadline,
) -> Result<()> {
    let now_us = now_unix_micros()?;
    let (batch, key) = {
        let reads = store.reads.clone();
        let generation = store.generation;
        let owner = owner.clone();
        let project = project.clone();
        let session_id = session_id.clone();
        let reason = reason.to_owned();
        store
            .pool
            .run_owned(deadline, move || {
                let phase = reads.read_phase().map_err(|e| store_error(&e))?;
                let current_owner = phase.runtime_owner().map_err(|e| store_error(&e))?;
                if !matches!(current_owner, se_types::Read::Present { value } if value.generation == generation)
                {
                    return crate::runtime::executor::close_read(
                        Err(se_core::scope::unreadable(
                            "external revoke generation",
                            "host generation changed",
                        )),
                        phase.close(),
                    );
                }
                let admission = Admission {
                    scope: Scope::Project(project.clone()),
                    actor: Actor::Human(owner),
                    session: None,
                    generation: generation.get(),
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
    store.submit_batch(batch, identity, deadline).await?;
    let mut revocations = crate::runtime::mail::Revocations::default();
    revocations
        .sessions
        .push((project.clone(), session_id.clone()));
    if let Some((cred_id, _)) = cred {
        revocations.credentials.push((project.clone(), cred_id));
    }
    let _ = store.mail_waits.revoked(&revocations);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_revocation_on_execution(
    execution: &crate::runtime::ExecutionContext,
    owner: &se_types::HumanId,
    project: &ProjectId,
    session_id: &SessionId,
    session_rev: Revision,
    cred: Option<(RecordId, Revision)>,
    reason: &str,
    deadline: &Deadline,
) -> Result<()> {
    let now_us = now_unix_micros()?;
    let (batch, key) = {
        let reads = execution.reads.clone();
        let generation = execution.generation;
        let owner = owner.clone();
        let project = project.clone();
        let session_id = session_id.clone();
        let reason = reason.to_owned();
        execution
            .blocking
            .run_owned(deadline, move || {
                let phase = reads.read_phase().map_err(|e| store_error(&e))?;
                let current_owner = phase.runtime_owner().map_err(|e| store_error(&e))?;
                if !matches!(current_owner, se_types::Read::Present { value } if value.generation == generation)
                {
                    return crate::runtime::executor::close_read(
                        Err(se_core::scope::unreadable(
                            "external revoke generation",
                            "host generation changed",
                        )),
                        phase.close(),
                    );
                }
                let admission = Admission {
                    scope: Scope::Project(project.clone()),
                    actor: Actor::Human(owner),
                    session: None,
                    generation: generation.get(),
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
    submit::submit(execution, batch, &identity, deadline).await?;

    // Immediately wake any parked wait channel for this session/credential.
    let mut revocations = crate::runtime::mail::Revocations::default();
    revocations
        .sessions
        .push((project.clone(), session_id.clone()));
    if let Some((cred_id, _)) = cred {
        revocations.credentials.push((project.clone(), cred_id));
    }
    let _ = execution.mail_waits.revoked(&revocations);
    Ok(())
}

pub(crate) fn find_active_external_session(
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
            let (session_id, lease_generation) = match &session_rec.current.body {
                EventBody::SessionActivated {
                    session,
                    containment:
                        ContainmentFact::ExternalSeat {
                            lease_generation, ..
                        },
                    ..
                } => (session.clone(), Some(*lease_generation)),
                EventBody::SessionActivated { session, .. }
                | EventBody::SessionPrepared { session, .. } => (session.clone(), None),
                _ => continue,
            };
            let cred_id = external_credential_id(&session_id)?;
            return Ok(ActiveExternalSession {
                session_id,
                session_rev: session_rec.revision,
                lease_generation,
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

pub(crate) fn rev(v: u64) -> Revision {
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
