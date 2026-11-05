//! Store barriers for one owned native lifecycle. All batches use the ordinary
//! admitted writer and its canonical FULL commit; native effects occur between
//! these barriers, never inside a snapshot.
mod capture;
mod launch;
pub use capture::{capture_failure, capture_verified, final_capture_failure};
pub use launch::{
    Activation, CaptureActivation, CredentialActivation, activate, reserve, transition,
};

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
pub fn session_credential_id(session: &se_types::SessionId, purpose: &str) -> Result<RecordId> {
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
/// Revocation is committed before the pin is removed or the session is terminal.
/// Failed preparations use SessionRevoked, so they cannot accumulate as live.
pub fn retire_session<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    active: bool,
    reason: String,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    retire_binding(kernel, plan.session.clone(), active, reason, cx)
}
pub fn retire_binding<R: Snapshot>(
    kernel: &Kernel,
    session: se_types::SessionId,
    active: bool,
    reason: String,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let mut bodies = Vec::with_capacity(3);
    for purpose in ["session", "http"] {
        bodies.push(EventBody::CredentialRevoked {
            credential: session_credential_id(&session, purpose)?,
            expected: revision(if active { 2 } else { 1 })?,
            reason: InputText::Inline(reason.clone()),
        });
    }
    bodies.push(if active {
        EventBody::SessionEnded {
            session: session.clone(),
            expected: revision(2)?,
            reason: InputText::Inline(reason),
            final_turn: None,
            final_cursor: None,
        }
    } else {
        EventBody::SessionRevoked {
            session: session.clone(),
            expected: revision(1)?,
            reason: InputText::Inline(reason),
        }
    });
    batch(
        kernel,
        "agent.launch",
        phase_key(&session.as_str().parse()?, "retire-session")?,
        serde_json::json!({"session":session,"phase":"retire-session"}),
        bodies,
        cx,
    )
}

/// Close external admission before potentially failing final transcript capture.
pub fn revoke_binding<R: Snapshot>(
    kernel: &Kernel,
    session: se_types::SessionId,
    active: bool,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let mut bodies = Vec::with_capacity(2);
    for purpose in ["session", "http"] {
        bodies.push(EventBody::CredentialRevoked {
            credential: session_credential_id(&session, purpose)?,
            expected: revision(if active { 2 } else { 1 })?,
            reason: InputText::Inline("native lifecycle cleanup; external admission closed".into()),
        });
    }
    batch(
        kernel,
        "agent.launch",
        phase_key(&session.as_str().parse()?, "revoke-credentials")?,
        serde_json::json!({"session":session,"phase":"revoke-credentials"}),
        bodies,
        cx,
    )
}
/// End the externally revoked session after its final capture completed.
pub fn end_binding<R: Snapshot>(
    kernel: &Kernel,
    session: se_types::SessionId,
    active: bool,
    reason: String,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let body = if active {
        EventBody::SessionEnded {
            session: session.clone(),
            expected: revision(2)?,
            reason: InputText::Inline(reason),
            final_turn: None,
            final_cursor: None,
        }
    } else {
        EventBody::SessionRevoked {
            session: session.clone(),
            expected: revision(1)?,
            reason: InputText::Inline(reason),
        }
    };
    batch(
        kernel,
        "agent.launch",
        phase_key(&session.as_str().parse()?, "end-session")?,
        serde_json::json!({"session":session,"phase":"end-session"}),
        vec![body],
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

/// Publish reconciliation under successor ownership. Lost is an internal
/// transition in the same FULL batch, so no caller observes a temporary grant.
pub fn reconcile<R: Snapshot>(
    kernel: &Kernel,
    previous: se_store::ProjectionRecord,
    identity: ProcessIdentityRecord,
    target: ProcessState,
    reason: String,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let from = match previous.current.body {
        EventBody::ProcessRegistered { initial, .. } => initial,
        EventBody::ProcessTransition { to, .. } => to,
        _ => {
            return Err(scope::unreadable(
                "reconciliation projection",
                "wrong process event",
            ));
        }
    };
    if !matches!(
        target,
        ProcessState::Running | ProcessState::StopUnproved | ProcessState::Exited
    ) {
        return Err(se_types::SeError::invalid(
            "reconciliation result",
            "running, proved exited or explicitly unproved",
        ));
    }
    // Native custody can be proved before provider reconnect fails. Each
    // distinct result is its own retryable barrier in this host generation.
    let key: IdempotencyKey = format!(
        "reconcile-{}-{}-{target:?}",
        cx.admission.generation, identity.record
    )
    .parse()?;
    let mut bodies = Vec::new();
    let mut expected = previous.revision;
    let mut observation = previous.current.header.event;
    let mut current = from;
    if target != ProcessState::Exited
        && from != ProcessState::Lost
        && !(from == ProcessState::StopRequested && target == ProcessState::StopUnproved)
    {
        bodies.push(EventBody::ProcessTransition {
            process: identity.record.clone(),
            identity: Box::new(identity.clone()),
            expected: Expected::Revision(expected),
            from,
            to: ProcessState::Lost,
            observation,
            outcome: "successor host reconciling retained custody".into(),
            containment: identity.containment.clone(),
        });
        expected = Revision {
            value: NonZeroU64::new(
                expected
                    .value
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| scope::unreadable("recovery revision", "exhausted"))?,
            )
            .ok_or_else(|| scope::unreadable("recovery revision", "zero"))?,
        };
        observation = kernel.facts()?.event.clone();
        current = ProcessState::Lost;
    }
    let lifecycle = identity.record.clone();
    bodies.push(EventBody::ProcessTransition {
        process: lifecycle.clone(),
        identity: Box::new(identity.clone()),
        expected: Expected::Revision(expected),
        from: current,
        to: target,
        observation,
        outcome: reason,
        containment: identity.containment,
    });
    batch(
        kernel,
        "agent.reconcile",
        key,
        serde_json::json!({"lifecycle":lifecycle,"generation":cx.admission.generation,"result":format!("{target:?}")}),
        bodies,
        cx,
    )
}
