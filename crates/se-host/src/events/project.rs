//! Projection of committed `StoredEvent`s into erasure-safe `EventPushFrame`s.
//!
//! Erasure invariant: `mail.notice` frames carry ONLY IDs, cursor, routing
//! metadata, and a body-free dedupe digest — NEVER message bodies. `decision`
//! frames likewise carry ONLY IDs and transition metadata — NEVER statement or
//! rationale bodies. Clients fetch bodies via bounded read operations so
//! `se forget` remains authoritative.
use super::{EventPushFrame, EventStreamKind, cursor};
use se_store::{Actor, EventBody, EventKind, Scope, StoreInfo, StoredEvent};
use se_types::{Generation, Result};
use serde_json::json;
use sha2::{Digest, Sha256};

/// Map an optional `EventStreamKind` filter to the exact SQLite `EventKind` set
/// queried by `Snapshot::history`.
pub(crate) fn event_kinds_for_filter(filter: Option<&[EventStreamKind]>) -> Vec<EventKind> {
    let selected = match filter {
        Some(kinds) if !kinds.is_empty() => kinds,
        _ => EventStreamKind::ALL,
    };
    let mut out = Vec::new();
    for kind in selected {
        match kind {
            EventStreamKind::MailNotice => out.extend_from_slice(&[
                EventKind::MessageSent,
                EventKind::WorkMessageSent,
                EventKind::MessageDelivered,
                EventKind::MessageRead,
                EventKind::MessageDismissed,
                EventKind::MessageSuperseded,
            ]),
            EventStreamKind::AgentState => out.extend_from_slice(&[
                EventKind::ProcessRegistered,
                EventKind::ProcessTransition,
                EventKind::AgentRetired,
            ]),
            EventStreamKind::Assignment => out.extend_from_slice(&[
                EventKind::AssignmentOpened,
                EventKind::AssignmentTransitioned,
            ]),
            EventStreamKind::Decision => out.extend_from_slice(&[
                EventKind::DecisionProposed,
                EventKind::DecisionRatified,
                EventKind::DecisionRejected,
                EventKind::DecisionRetracted,
                EventKind::DecisionSuperseded,
            ]),
            EventStreamKind::SessionHold => out.extend_from_slice(&[
                EventKind::SessionPrepared,
                EventKind::SessionActivated,
                EventKind::SessionEnded,
            ]),
            EventStreamKind::SessionRevoke => {
                out.extend_from_slice(&[EventKind::SessionRevoked, EventKind::CredentialRevoked])
            }
        }
    }
    out
}

/// Exact session binding for `SubscribePrincipal::Session` callers.
///
/// Session-owned lifecycle events (`AgentState` process events, `SessionHold`,
/// and `SessionRevoke`) are strictly gated to the authenticated session or
/// credential so events from another session of the same agent never leak.
/// Agent-scoped notices (`MailNotice`, `Assignment`, `Decision`) remain visible
/// across that agent's sessions per `Visibility::SelfOnly(agent)`.
pub(crate) struct SessionScope<'a> {
    pub(crate) agent: &'a se_types::AgentId,
    pub(crate) session: &'a se_types::SessionId,
    pub(crate) credential: se_store::RecordId,
}

fn session_scope_allows(event: &StoredEvent, scope: &SessionScope<'_>) -> bool {
    match &event.body {
        EventBody::ProcessRegistered { identity, .. }
        | EventBody::ProcessTransition { identity, .. } => {
            identity.session.as_ref() == Some(scope.session)
        }
        EventBody::AgentRetired {
            agent,
            final_session,
            ..
        } => {
            agent == scope.agent
                && (final_session.is_none() || final_session.as_ref() == Some(scope.session))
        }
        EventBody::SessionPrepared { session, .. }
        | EventBody::SessionActivated { session, .. }
        | EventBody::SessionEnded { session, .. }
        | EventBody::SessionRevoked { session, .. } => session == scope.session,
        EventBody::CredentialRevoked { credential, .. } => *credential == scope.credential,
        _ => true,
    }
}

/// Project one authorized `StoredEvent` into an `EventPushFrame` if its kind
/// belongs to the stream catalogue (and passes `filter` and exact-session scope).
pub(crate) fn project_event(
    event: &StoredEvent,
    info: &StoreInfo,
    generation: Generation,
    filter: Option<&[EventStreamKind]>,
    session_scope: Option<&SessionScope<'_>>,
) -> Result<Option<EventPushFrame>> {
    if let Some(scope) = session_scope
        && !session_scope_allows(event, scope)
    {
        return Ok(None);
    }
    let project_id = match &event.header.scope {
        Scope::Project(id) => Some(id.as_str()),
        Scope::Registry => None,
    };
    let seq = event.position.sequence();
    let Some((kind, payload)) = project_body(event, project_id, seq) else {
        return Ok(None);
    };
    if let Some(allowed) = filter
        && !allowed.is_empty()
        && !allowed.contains(&kind)
    {
        return Ok(None);
    }
    let cur = cursor::encode(info, generation, seq)?;
    Ok(Some(EventPushFrame {
        cursor: cur,
        event_id: event.header.event.clone(),
        kind,
        occurred_at_us: event.header.occurred_at_us,
        payload,
    }))
}

fn dedupe_digest(event_id: &se_types::EventId, subject_id: &str, seq: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(subject_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(seq.to_be_bytes());
    se_types::hex_lower(&hasher.finalize())
}

fn actor_json(actor: &Actor) -> serde_json::Value {
    match actor {
        Actor::Human(id) => json!({"kind": "owner", "id": id}),
        Actor::Agent(id) => json!({"kind": "agent", "id": id}),
        Actor::Remote(id) => json!({"kind": "remote", "id": id}),
        Actor::Guest => json!({"kind": "guest"}),
    }
}

fn project_body(
    event: &StoredEvent,
    project_id: Option<&str>,
    seq: u64,
) -> Option<(EventStreamKind, serde_json::Value)> {
    project_mail_event(event, project_id, seq)
        .or_else(|| project_agent_or_assignment(event, project_id))
        .or_else(|| project_decision(event, project_id))
        .or_else(|| project_session(event, project_id))
}

fn project_mail_event(
    event: &StoredEvent,
    project_id: Option<&str>,
    seq: u64,
) -> Option<(EventStreamKind, serde_json::Value)> {
    match &event.body {
        // Erasure rule: mail.notice NEVER includes message body text.
        EventBody::MessageSent {
            message,
            recipient,
            kind,
            body: _,
            refs: _,
            reply_to,
            quiet,
        } => Some((
            EventStreamKind::MailNotice,
            json!({
                "project_id": project_id,
                "message_id": message,
                "action": "sent",
                "from": actor_json(&event.header.actor),
                "to": actor_json(recipient),
                "message_kind": kind,
                "reply_to": reply_to,
                "quiet": quiet,
                "dedupe_digest": dedupe_digest(&event.header.event, message.as_str(), seq),
            }),
        )),
        EventBody::WorkMessageSent {
            message,
            work,
            kind,
            body: _,
            refs: _,
            reply_to,
            quiet,
        } => Some((
            EventStreamKind::MailNotice,
            json!({
                "project_id": project_id,
                "message_id": message,
                "action": "work_sent",
                "from": actor_json(&event.header.actor),
                "work_action": work.action,
                "addressees": work.addressees,
                "message_kind": kind,
                "reply_to": reply_to,
                "quiet": quiet,
                "dedupe_digest": dedupe_digest(&event.header.event, message.as_str(), seq),
            }),
        )),
        EventBody::MessageDelivered {
            message, recipient, ..
        } => Some((
            EventStreamKind::MailNotice,
            json!({
                "project_id": project_id,
                "message_id": message,
                "action": "delivered",
                "recipient": actor_json(recipient),
                "dedupe_digest": dedupe_digest(&event.header.event, message.as_str(), seq),
            }),
        )),
        EventBody::MessageRead { message, recipient } => Some((
            EventStreamKind::MailNotice,
            json!({
                "project_id": project_id,
                "message_id": message,
                "action": "read",
                "recipient": actor_json(recipient),
                "dedupe_digest": dedupe_digest(&event.header.event, message.as_str(), seq),
            }),
        )),
        EventBody::MessageDismissed { message, recipient } => Some((
            EventStreamKind::MailNotice,
            json!({
                "project_id": project_id,
                "message_id": message,
                "action": "dismissed",
                "recipient": actor_json(recipient),
                "dedupe_digest": dedupe_digest(&event.header.event, message.as_str(), seq),
            }),
        )),
        EventBody::MessageSuperseded {
            message,
            replacement,
            ..
        } => Some((
            EventStreamKind::MailNotice,
            json!({
                "project_id": project_id,
                "message_id": message,
                "action": "superseded",
                "replacement": replacement,
                "dedupe_digest": dedupe_digest(&event.header.event, message.as_str(), seq),
            }),
        )),
        _ => None,
    }
}

fn project_agent_or_assignment(
    event: &StoredEvent,
    project_id: Option<&str>,
) -> Option<(EventStreamKind, serde_json::Value)> {
    match &event.body {
        EventBody::ProcessRegistered { identity, initial } => Some((
            EventStreamKind::AgentState,
            json!({
                "project_id": project_id,
                "principal": actor_json(&identity.principal),
                "lifecycle_id": identity.record,
                "session_id": identity.session,
                "state": initial.as_str(),
            }),
        )),
        EventBody::ProcessTransition {
            process,
            identity,
            from,
            to,
            ..
        } => Some((
            EventStreamKind::AgentState,
            json!({
                "project_id": project_id,
                "principal": actor_json(&identity.principal),
                "lifecycle_id": process,
                "session_id": identity.session,
                "from_state": from.as_str(),
                "state": to.as_str(),
            }),
        )),
        EventBody::AgentRetired {
            agent,
            reason,
            final_session,
        } => Some((
            EventStreamKind::AgentState,
            json!({
                "project_id": project_id,
                "agent_id": agent,
                "state": "retired",
                "reason": reason,
                "session_id": final_session,
            }),
        )),
        EventBody::AssignmentOpened {
            project,
            assignment,
            assignee,
            floor_event,
            ..
        } => Some((
            EventStreamKind::Assignment,
            json!({
                "project_id": project,
                "assignment_id": assignment,
                "action": "open",
                "assignee": assignee,
                "floor_event": floor_event,
            }),
        )),
        EventBody::AssignmentTransitioned {
            assignment,
            action,
            floor_event,
            ..
        } => Some((
            EventStreamKind::Assignment,
            json!({
                "project_id": project_id,
                "assignment_id": assignment,
                "action": action,
                "floor_event": floor_event,
            }),
        )),
        _ => None,
    }
}

fn project_decision(
    event: &StoredEvent,
    project_id: Option<&str>,
) -> Option<(EventStreamKind, serde_json::Value)> {
    match &event.body {
        // Erasure rule: decision frames carry IDs and metadata only, never text bodies.
        EventBody::DecisionProposed {
            decision,
            key,
            prior,
            kind,
            ..
        } => Some((
            EventStreamKind::Decision,
            json!({
                "project_id": project_id,
                "decision_id": decision,
                "action": "proposed",
                "key": key,
                "prior": prior,
                "decision_kind": kind,
            }),
        )),
        EventBody::DecisionRatified { decision, .. } => Some((
            EventStreamKind::Decision,
            json!({
                "project_id": project_id,
                "decision_id": decision,
                "action": "ratified",
            }),
        )),
        EventBody::DecisionRejected { decision, .. } => Some((
            EventStreamKind::Decision,
            json!({
                "project_id": project_id,
                "decision_id": decision,
                "action": "rejected",
            }),
        )),
        EventBody::DecisionRetracted { decision, .. } => Some((
            EventStreamKind::Decision,
            json!({
                "project_id": project_id,
                "decision_id": decision,
                "action": "retracted",
            }),
        )),
        EventBody::DecisionSuperseded {
            prior, replacement, ..
        } => Some((
            EventStreamKind::Decision,
            json!({
                "project_id": project_id,
                "decision_id": prior,
                "replacement": replacement,
                "action": "superseded",
            }),
        )),
        _ => None,
    }
}

fn project_session(
    event: &StoredEvent,
    project_id: Option<&str>,
) -> Option<(EventStreamKind, serde_json::Value)> {
    match &event.body {
        EventBody::SessionPrepared {
            session,
            agent,
            surface,
            ..
        } => Some((
            EventStreamKind::SessionHold,
            json!({
                "project_id": project_id,
                "session_id": session,
                "agent_id": agent,
                "state": "prepared",
                "surface": surface.map(|s| s.as_str()),
            }),
        )),
        EventBody::SessionActivated { session, .. } => Some((
            EventStreamKind::SessionHold,
            json!({
                "project_id": project_id,
                "session_id": session,
                "state": "activated",
            }),
        )),
        EventBody::SessionEnded { session, .. } => Some((
            EventStreamKind::SessionHold,
            json!({
                "project_id": project_id,
                "session_id": session,
                "state": "ended",
            }),
        )),
        EventBody::SessionRevoked { session, .. } => Some((
            EventStreamKind::SessionRevoke,
            json!({
                "project_id": project_id,
                "session_id": session,
                "state": "revoked",
            }),
        )),
        EventBody::CredentialRevoked { credential, .. } => Some((
            EventStreamKind::SessionRevoke,
            json!({
                "project_id": project_id,
                "credential_id": format!("{credential:?}"),
                "state": "revoked",
            }),
        )),
        _ => None,
    }
}
