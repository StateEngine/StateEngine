//! Closed delegated exposure. No remote grant becomes local Owner/session authority.
use crate::scope;
mod launch;
mod launch_receipt;
pub use launch::{launch_key, plan_launch};
pub use launch_receipt::{launch_activated, read_launch_receipt};
use se_store::{
    Actor, Admission, AtomicBatch, EventBody, EventHeader, InputText, IntentDigest, NewEvent,
    RequestIdentity, Scope, StoreInfo,
    remote::{GrantRecord, GrantState, MessageAttribution},
};
use se_types::{
    EventId, MessageId, Result,
    remote::{RemoteAttribution, RemoteSend, RemoteTarget, RemoteVerb},
};
use sha2::{Digest, Sha256};

/// Produced after fresh machine-session authorization; not a wire capability.
/// One request consumes this value. A later request needs current grant facts again.
pub struct RemoteAdmission {
    grant: GrantRecord,
    verb: RemoteVerb,
    targets: Vec<RemoteTarget>,
}
impl RemoteAdmission {
    pub fn grant(&self) -> &GrantRecord {
        &self.grant
    }
    pub fn targets(&self) -> &[RemoteTarget] {
        &self.targets
    }
    pub fn verb(&self) -> &RemoteVerb {
        &self.verb
    }
}
pub fn authorize(
    grant: GrantRecord,
    verb: RemoteVerb,
    targets: &[RemoteTarget],
    now: i64,
) -> Result<RemoteAdmission> {
    if grant.state != GrantState::Active
        || grant.expires_at_us <= now
        || !grant.scope.verbs.contains(&verb)
    {
        return Err(scope::unreadable(
            "remote grant",
            "machine session is expired, revoked or does not permit this operation; the machine owner can explicitly reconnect with se remote add",
        ));
    }
    grant.scope.validate()?;
    let targets = if targets.is_empty() {
        grant.scope.targets.clone()
    } else {
        targets.to_vec()
    };
    if (targets.is_empty() && verb != RemoteVerb::List)
        || targets.len() > 64
        || targets.iter().any(|t| !grant.scope.allows(verb, t))
    {
        return Err(scope::unreadable(
            "remote scope",
            "requested target is outside the machine session's scope; select an authorized target",
        ));
    }
    Ok(RemoteAdmission {
        grant,
        verb,
        targets,
    })
}

/// Launch is a separate Owner decision; legacy scope verbs do not imply it.
/// The native adapter supplies the permission from the same fresh store pin.
pub fn authorize_launch(
    grant: GrantRecord,
    target: &RemoteTarget,
    permission: se_store::remote::LaunchPermission,
    now: i64,
) -> Result<RemoteAdmission> {
    if grant.state != GrantState::Active
        || grant.expires_at_us <= now
        || permission.grant != grant.grant
        || permission.target != *target
        || !permission.allowed
    {
        return Err(scope::unreadable(
            "remote launch consent",
            "the destination Owner has not allowed this paired machine to start this saved agent; run se remote permissions --name <saved-alias> --launch in a terminal and choose this agent",
        ));
    }
    grant.scope.validate()?;
    Ok(RemoteAdmission {
        grant,
        verb: RemoteVerb::Launch,
        targets: vec![target.clone()],
    })
}

/// Adapter allocations and current store/host facts, obtained before submission.
pub struct RemoteSendFacts {
    pub store: StoreInfo,
    pub generation: u64,
    pub occurred_at_us: i64,
    pub message: MessageId,
    pub sent_event: EventId,
    pub attribution_event: EventId,
}
/// Uses the ordinary message transaction/projection and original keyed receipt.
/// No native/provider call or separate remote operation log is introduced.
pub fn plan_send(
    admission: RemoteAdmission,
    input: RemoteSend,
    attribution: RemoteAttribution,
    facts: RemoteSendFacts,
) -> Result<AtomicBatch> {
    if admission.verb != RemoteVerb::Send
        || admission.targets.as_slice() != [input.target.clone()]
        || input.body.is_empty()
        || input.body.len() > se_types::MESSAGE_BODY_MAX_BYTES
        || admission.grant.store != facts.store.id
        || admission.grant.expires_at_us <= facts.occurred_at_us
    {
        return Err(scope::unreadable(
            "remote send",
            "send requires the exact granted target, current session and 1..32768 UTF-8 bytes",
        ));
    }
    let key = request_key(&attribution, &input.idempotency_key)?;
    let origin = attribution.source.as_ref().map(|source| source.address());
    let grant = admission.grant;
    let intent=serde_json::to_vec(&serde_json::json!({"operation":"remote.send","codec_version":1,"source":origin,"grant":grant.grant,"authority_revision":grant.authority_revision,"target":input.target,"session":input.session,"body":input.body})).map_err(|e|scope::unreadable("remote send intent",&e.to_string()))?;
    let local = Admission {
        scope: Scope::Project(input.target.project.clone()),
        actor: Actor::Remote(grant.principal.clone()),
        session: None,
        generation: facts.generation,
    };
    let header = |event| EventHeader {
        event,
        scope: local.scope.clone(),
        actor: local.actor.clone(),
        session: None,
        origin: facts.store.id.clone(),
        door: se_store::Door::Host,
        occurred_at_us: facts.occurred_at_us,
        cause: None,
        supersedes: None,
    };
    let record = MessageAttribution {
        message: facts.message.clone(),
        principal: grant.principal,
        grant: grant.grant,
        authority_revision: grant.authority_revision,
        target: input.target.clone(),
        expected_session: input.session,
        attribution,
    };
    Ok(AtomicBatch {
        expected_incarnation: facts.store.incarnation,
        admission: local.clone(),
        request: Some(RequestIdentity {
            key,
            intent: IntentDigest {
                operation: "remote.send",
                codec_version: 1,
                sha256: Sha256::digest(intent).into(),
            },
        }),
        events: vec![
            NewEvent {
                header: header(facts.sent_event),
                body: EventBody::MessageSent {
                    message: facts.message,
                    recipient: Actor::Agent(input.target.agent),
                    kind: "note".into(),
                    body: InputText::Inline(input.body.into()),
                    quiet: false,
                    refs: Vec::new(),
                    reply_to: None,
                },
            },
            NewEvent {
                header: header(facts.attribution_event),
                body: EventBody::RemoteMessageAttributed { record },
            },
        ],
        import_checkpoint: None,
    })
}

/// Machine sessions share a writer principal; request keys must still distinguish
/// real sending agents. Session/generation deliberately do not enter this key.
pub fn request_key(
    attribution: &RemoteAttribution,
    key: &se_types::IdempotencyKey,
) -> Result<se_types::IdempotencyKey> {
    let origin = attribution.source.as_ref().map(|source| source.address());
    let bytes = serde_json::to_vec(&("remote-message/v1", origin, key))
        .map_err(|_| scope::unreadable("remote request key", "stable origin encoding failed"))?;
    se_types::IdempotencyKey::new(format!(
        "remote-{}",
        se_types::hex_lower(&Sha256::digest(bytes))
    ))
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use se_types::remote::*;
    #[test]
    fn successor_session_retries_share_a_key_but_distinct_agents_do_not() -> Result<()> {
        let id = |n| se_types::Sha256::from_bytes([n; 32]);
        let mut attribution = RemoteAttribution {
            host: RemoteHostId(id(1)),
            store: se_types::StoreId::from_parts(1700000000000, [1; 10])?,
            principal: se_types::RemotePrincipalId::from_parts(1700000000000, [2; 10])?,
            grant: se_types::RemoteGrantId::from_parts(1700000000000, [3; 10])?,
            device: se_types::RemoteDeviceId::from_parts(1700000000000, [4; 10])?,
            authority_revision: 1,
            source: Some(RemoteSourceSession {
                host: RemoteHostId(id(2)),
                project: se_types::ProjectId::from_parts(1700000000000, [5; 10])?,
                agent: se_types::AgentId::from_parts(1700000000000, [6; 10])?,
                session: se_types::SessionId::from_parts(1700000000000, [7; 10])?,
                generation: se_types::Generation::new(1)?,
            }),
        };
        let key = se_types::IdempotencyKey::new("same-public-request-key")?;
        let original = request_key(&attribution, &key)?;
        if let Some(source) = &mut attribution.source {
            source.session = se_types::SessionId::from_parts(1700000000000, [8; 10])?;
            source.generation = se_types::Generation::new(2)?;
        }
        assert_eq!(request_key(&attribution, &key)?, original);
        if let Some(source) = &mut attribution.source {
            source.agent = se_types::AgentId::from_parts(1700000000000, [9; 10])?;
        }
        assert_ne!(request_key(&attribution, &key)?, original);
        Ok(())
    }
}
