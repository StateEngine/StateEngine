//! Store barriers for one owned native lifecycle. All batches use the ordinary
//! admitted writer and its canonical FULL commit; native effects occur between
//! these barriers, never inside a snapshot.
use super::agent_launch::LaunchPlan;
use crate::{commit::Cx, dispatch::Kernel, scope};
use se_store::{
    AtomicBatch, EventBody, Expected, InputText, ProcessIdentityRecord, ProcessState, RecordId,
    RecordIdentity, Revision, Snapshot,
};
use se_types::{EventId, IdempotencyKey, Result};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

pub fn credential_id(plan: &LaunchPlan, purpose: &str) -> Result<RecordId> {
    session_credential_id(&plan.session, purpose)
}
fn session_credential_id(session: &se_types::SessionId, purpose: &str) -> Result<RecordId> {
    let bytes = session
        .canonical_bytes()?
        .ok_or_else(|| scope::unreadable("launch session", "noncanonical identity"))?;
    let mut time = [0; 8];
    time[2..].copy_from_slice(&bytes[..6]);
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.update(purpose.as_bytes());
    let mut random = [0; 10];
    random.copy_from_slice(&digest.finalize()[..10]);
    RecordId::from_parts(u64::from_be_bytes(time), random)
        .map_err(|e| crate::store_error::store_error(&e))
}
pub fn phase_key(key: &IdempotencyKey, phase: &str) -> Result<IdempotencyKey> {
    let mut hash = Sha256::new();
    hash.update(key.as_str());
    hash.update([0]);
    hash.update(phase);
    let value = hash.finalize();
    format!(
        "process-{}",
        value.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
    .parse()
}
fn revision(value: u64) -> Result<Expected> {
    Ok(Expected::Revision(Revision {
        value: NonZeroU64::new(value)
            .ok_or_else(|| scope::unreadable("lifecycle revision", "zero revision"))?,
    }))
}
/// This helper is private: adapters cannot submit arbitrary operation bodies
/// through this module. Each public barrier below fixes the required ordering.
pub(crate) fn batch<R: Snapshot>(
    kernel: &Kernel,
    operation: &'static str,
    key: IdempotencyKey,
    intent: serde_json::Value,
    bodies: Vec<EventBody<InputText>>,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let mut events = Vec::with_capacity(bodies.len());
    for (index, body) in bodies.into_iter().enumerate() {
        let mut event = kernel.event(body, cx)?;
        if index != 0 {
            let seed =
                kernel.facts()?.event.canonical_bytes()?.ok_or_else(|| {
                    scope::unreadable("lifecycle event", "noncanonical allocation")
                })?;
            let mut hash = Sha256::new();
            hash.update(seed);
            hash.update((index as u64).to_le_bytes());
            let mut random = [0; 10];
            random.copy_from_slice(&hash.finalize()[..10]);
            let mut time = [0; 8];
            time[2..].copy_from_slice(&seed[..6]);
            event.header.event = EventId::from_parts(u64::from_be_bytes(time), random)?;
        }
        events.push(event);
    }
    let mut events = events.into_iter();
    let first = events
        .next()
        .ok_or_else(|| scope::unreadable("lifecycle barrier", "empty transaction"))?;
    let mut batch = kernel.batch(operation, key, intent, first, cx)?;
    batch.events.extend(events);
    Ok(batch)
}
/// C1: process reservation and both prepared credentials precede all native
/// creation. Hashes bind the exact delivered sec1 and sels token bytes.
pub fn reserve<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    identity: ProcessIdentityRecord,
    session_hash: [u8; 32],
    http_hash: [u8; 32],
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let now = kernel.facts()?.occurred_at_us;
    let deadline = now
        .checked_add(600_000_000)
        .ok_or_else(|| scope::unreadable("credential deadline", "clock overflow"))?;
    let expires = now
        .checked_add(86_400_000_000)
        .ok_or_else(|| scope::unreadable("credential expiry", "clock overflow"))?;
    let mut bodies = vec![
        super::session_commit::prepare(super::session_commit::SessionPreparation {
            session: plan.session.clone(),
            agent: plan.agent.id.clone(),
            provider: plan.profile.provider,
            native_ref: match &plan.conversation {
                se_types::Read::Present { value } => value.to_string(),
                _ => plan.session.as_str()[se_types::SessionId::PREFIX.len()..].into(),
            },
            consent: if plan.capture {
                se_store::Consent::Capture
            } else {
                se_store::Consent::Suppressed
            },
            generation: cx.admission.generation,
            expected: Expected::Absent,
        })?,
        EventBody::ProcessRegistered {
            identity: Box::new(identity),
            initial: ProcessState::Reserved,
        },
    ];
    // Re-read the control grant and preparations in the same finite planning
    // snapshot. No new native effect may coexist with an unreleased lifecycle.
    let current = scope::require_present(
        cx.read
            .control_target(plan.agent.id.clone())
            .map_err(|e| crate::store_error::store_error(&e))?,
        "launch control",
        "Restore the current create grant or use the owner's terminal.",
    )?;
    if !current.processes.is_empty() {
        return Err(se_types::SeError::invalid(
            "launch target",
            "stop or reconcile the target's owned lifecycle before launching again",
        ));
    }
    for old in current.sessions {
        let (session, provider) = match &old.current.body {
            EventBody::SessionPrepared {
                session, provider, ..
            } => (session, *provider),
            _ => {
                return Err(se_types::SeError::invalid(
                    "launch target",
                    "stop its active session before launching again",
                ));
            }
        };
        if provider != se_store::Provider::Claude {
            return Err(se_types::SeError::invalid(
                "launch preparation",
                "reconcile the existing provider preparation before changing provider",
            ));
        }
        // Managed Claude preparations have exactly these two capabilities;
        // missing or independently changed credentials refuse the whole batch.
        for purpose in ["session", "http"] {
            bodies.push(EventBody::CredentialRevoked {
                credential: session_credential_id(session, purpose)?,
                expected: revision(1)?,
                reason: InputText::Inline(
                    "superseded by a newer managed launch preparation".into(),
                ),
            });
        }
        bodies.push(EventBody::SessionRevoked {
            session: session.clone(),
            expected: Expected::Revision(old.revision),
            reason: InputText::Inline("superseded by a newer managed launch preparation".into()),
        });
    }
    for (purpose, hash) in [("session", session_hash), ("http", http_hash)] {
        bodies.push(EventBody::CredentialIssued {
            credential: credential_id(plan, purpose)?,
            session: plan.session.clone(),
            purpose: purpose.into(),
            secret_sha256: hash,
            expires_at_us: expires,
            activation_deadline_us: deadline,
            expected: Expected::Absent,
        });
    }
    let mut intent = serde_json::to_value(&plan.input)
        .map_err(|e| scope::unreadable("launch intent", &e.to_string()))?;
    intent["selected_agent"] = serde_json::json!(plan.agent.id);
    batch(
        kernel,
        "agent.launch",
        plan.input.idempotency_key.clone(),
        intent,
        bodies,
        cx,
    )
}
/// C2 and the tracked-helper RootCheckpoint: the previous protected revision
/// and observation event come from the same admitted finite control read.
pub fn transition<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    phase: &str,
    previous: &se_store::ProjectionRecord,
    identity: ProcessIdentityRecord,
    edge: (ProcessState, ProcessState),
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let containment = identity.containment.clone();
    batch(
        kernel,
        "agent.launch",
        phase_key(&plan.input.idempotency_key, phase)?,
        serde_json::json!({"session":plan.session,"phase":phase}),
        vec![EventBody::ProcessTransition {
            process: plan.lifecycle.clone(),
            identity: Box::new(identity),
            expected: Expected::Revision(previous.revision),
            from: edge.0,
            to: edge.1,
            observation: previous.current.header.event.clone(),
            outcome: phase.into(),
            containment,
        }],
        cx,
    )
}
/// C3: native exec plus the owned stdout init echo have both been witnessed.
/// Running, session activation and both capabilities become visible atomically.
pub fn activate<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    previous: &se_store::ProjectionRecord,
    identity: ProcessIdentityRecord,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let containment = identity.containment.clone();
    let observation = previous.current.header.event.clone();
    let mut bodies = vec![
        EventBody::ProcessTransition {
            process: plan.lifecycle.clone(),
            identity: Box::new(identity),
            expected: Expected::Revision(previous.revision),
            from: ProcessState::Starting,
            to: ProcessState::Running,
            observation: observation.clone(),
            outcome: "provider-init-witnessed".into(),
            containment: containment.clone(),
        },
        super::session_commit::activate(super::session_commit::SessionActivation {
            session: plan.session.clone(),
            expected: revision(1)?,
            incumbent: None,
            process: Some(plan.lifecycle.clone()),
            containment,
            witnesses: vec![observation],
        })?,
    ];
    for purpose in ["session", "http"] {
        bodies.push(EventBody::CredentialActivated {
            credential: credential_id(plan, purpose)?,
            session: plan.session.clone(),
            expected: revision(1)?,
            first_request: credential_id(plan, "first-request")?,
        });
    }
    batch(
        kernel,
        "agent.launch",
        phase_key(&plan.input.idempotency_key, "activate")?,
        serde_json::json!({"session":plan.session,"phase":"activate"}),
        bodies,
        cx,
    )
}
/// Revocation is committed before the pin is removed or the session is terminal.
/// Failed preparations use SessionRevoked, so they cannot accumulate as live.
pub fn retire_session<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    active: bool,
    reason: String,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let mut bodies = Vec::with_capacity(3);
    for purpose in ["session", "http"] {
        bodies.push(EventBody::CredentialRevoked {
            credential: credential_id(plan, purpose)?,
            expected: revision(if active { 2 } else { 1 })?,
            reason: InputText::Inline(reason.clone()),
        });
    }
    bodies.push(if active {
        EventBody::SessionEnded {
            session: plan.session.clone(),
            expected: revision(2)?,
            reason: InputText::Inline(reason),
            final_turn: None,
            final_cursor: None,
        }
    } else {
        EventBody::SessionRevoked {
            session: plan.session.clone(),
            expected: revision(1)?,
            reason: InputText::Inline(reason),
        }
    });
    batch(
        kernel,
        "agent.launch",
        phase_key(&plan.input.idempotency_key, "retire-session")?,
        serde_json::json!({"session":plan.session,"phase":"retire-session"}),
        bodies,
        cx,
    )
}

/// One observed native transition under its original control request. The
/// lifecycle participates in the phase key so --all has independent CAS rows.
pub struct ProcessChange {
    pub request: IdempotencyKey,
    pub phase: &'static str,
    pub previous: se_store::ProjectionRecord,
    pub identity: ProcessIdentityRecord,
    pub edge: (ProcessState, ProcessState),
}
pub fn advance<R: Snapshot>(
    kernel: &Kernel,
    change: ProcessChange,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let lifecycle = change.identity.record.clone();
    let containment = change.identity.containment.clone();
    let key = phase_key(&change.request, &format!("{lifecycle}/{}", change.phase))?;
    let operation = if matches!(
        change.edge.1,
        ProcessState::StopRequested | ProcessState::StopUnproved
    ) {
        "agent.stop"
    } else {
        "agent.lifecycle"
    };
    batch(
        kernel,
        operation,
        key,
        serde_json::json!({"lifecycle":lifecycle,"phase":change.phase,"from":change.edge.0,"to":change.edge.1}),
        vec![EventBody::ProcessTransition {
            process: lifecycle,
            identity: Box::new(change.identity),
            expected: Expected::Revision(change.previous.revision),
            from: change.edge.0,
            to: change.edge.1,
            observation: change.previous.current.header.event,
            outcome: change.phase.into(),
            containment,
        }],
        cx,
    )
}
