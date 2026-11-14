//! Wire receipts are reconstructed from committed immutable events, never draft IDs.
use super::outputs::*;
use crate::{commit, scope, store_error::store_error};
use se_store::{
    Actor, CommitReceipt, EventBody, Snapshot, StoredEvent, StoredText, WriterModeValue,
};
use se_types::{AgentId, IdempotencyKey, Read, Result, SeError, UnixMicros};
use sha2::{Digest, Sha256};

pub fn timestamp(micros: i64) -> Result<String> {
    let micros = u64::try_from(micros)
        .map_err(|_| SeError::invalid("recorded_at", "nonnegative Unix microseconds"))?;
    let value = UnixMicros::new(micros)?.to_string();
    let value = value
        .strip_suffix(" UTC")
        .ok_or_else(|| scope::unreadable("UTC formatter", "missing UTC suffix"))?;
    Ok(format!("{}Z", value.replacen(' ', "T", 1)))
}
/// Imported user history reports its original time. Commit receipts continue
/// to report the separately retained native recording time.
pub(crate) fn event_time(event: &StoredEvent) -> i64 {
    if event.header.door == se_store::Door::Import {
        event.header.occurred_at_us
    } else {
        event.recorded_at_us
    }
}
pub fn writer(receipt: &CommitReceipt) -> Writer {
    match receipt.writer.kind() {
        se_store::WriterKind::Direct => Writer::Direct,
        se_store::WriterKind::Host { generation } => Writer::Host {
            host_generation: generation.to_string(),
        },
    }
}
pub fn commit_state(receipt: &CommitReceipt) -> CommitState {
    match receipt.state {
        se_store::CommitState::Committed => CommitState::Committed,
        se_store::CommitState::Replayed | se_store::CommitState::NaturalKeyReplay => {
            CommitState::Replayed
        }
    }
}
pub(crate) fn floor_ref() -> ActorRef {
    ActorRef {
        kind: "floor".into(),
        id: "floor".into(),
        name: "Shared work messages".into(),
    }
}
pub fn actor_ref<R: Snapshot>(read: &mut R, actor: &Actor) -> Result<ActorRef> {
    if let Actor::Remote(id) = actor {
        return Ok(ActorRef {
            kind: "remote".into(),
            id: id.to_string(),
            name: format!("Remote device {id}"),
        });
    }
    let record = scope::require_present(
        read.principal(actor.clone()).map_err(|e| store_error(&e))?,
        "receipt principal",
        "Verify the event's recorded principal in this project; when completing a write, preserve its original request key and event IDs.",
    )?;
    let name = match record.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name
        }
        _ => {
            return Err(scope::unreadable(
                "principal projection",
                "current event is not principal registration/rename",
            ));
        }
    };
    Ok(ActorRef {
        kind: match actor {
            Actor::Human(_) => "owner",
            Actor::Agent(_) => "agent",
            Actor::Remote(_) => "remote",
        }
        .into(),
        id: scope::actor_id(actor),
        name,
    })
}
/// Instruction standing belongs to this exact admitted message and recipient;
/// the sender remains its real remote principal, never a local Owner/Core actor.
pub fn mail_sender_ref<R: Snapshot>(
    read: &mut R,
    message: &se_store::MessageRecord,
) -> Result<ActorRef> {
    if let Actor::Remote(principal) = &message.sender {
        if let Some(address) = read
            .remote_return_sender(message.message.clone())
            .map_err(|e| store_error(&e))?
        {
            return Ok(ActorRef {
                kind: "remote_agent".into(),
                id: address.selector(),
                name: format!(
                    "Remote agent {} (project {}, machine {})",
                    address.agent,
                    address.project,
                    address.host.0.hex()
                ),
            });
        }
        let attribution = read
            .remote_message_attribution(message.message.clone())
            .map_err(|error| store_error(&error))?
            .ok_or_else(|| {
                scope::unreadable(
                    "mail sender provenance",
                    "the remote message has no verified original source",
                )
            })?;
        if attribution.principal != *principal {
            return Err(scope::unreadable(
                "mail sender provenance",
                "source principal differs from the committed sender",
            ));
        }
        return Ok(match attribution.source {
            Some(source) => ActorRef {
                kind: "remote_agent".into(),
                id: format!(
                    "{}/{}/{}",
                    source.host.0.hex(),
                    source.project,
                    source.agent
                ),
                name: format!(
                    "Remote agent {} (project {}, machine {})",
                    source.agent,
                    source.project,
                    source.host.0.hex()
                ),
            },
            None => ActorRef {
                kind: "remote_sender".into(),
                id: principal.to_string(),
                name: format!("Remote sender {principal}"),
            },
        });
    }
    actor_ref(read, &message.sender)
}
pub fn named_agent<R: Snapshot>(read: &mut R, agent: &AgentId) -> Result<Named<AgentId>> {
    let actor = actor_ref(read, &Actor::Agent(agent.clone()))?;
    Ok(Named {
        id: agent.clone(),
        name: actor.name,
    })
}
pub(crate) fn receipt_key(
    receipt: &CommitReceipt,
    expected: &IdempotencyKey,
    source: &str,
) -> Result<()> {
    if receipt.request_key.as_ref() != Some(expected)
        || !receipt.events.contains(&receipt.primary_event)
    {
        return Err(scope::unreadable(
            source,
            "request identity or primary event does not match the continuation",
        ));
    }
    Ok(())
}
pub(crate) fn committed_event<R: Snapshot>(
    read: &mut R,
    receipt: &CommitReceipt,
) -> Result<StoredEvent> {
    let event = scope::require_present(
        read.event(receipt.primary_event.clone())
            .map_err(|e| store_error(&e))?,
        "receipt primary event",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    if event.writer.kind() != receipt.writer.kind() || event.durability != receipt.durability {
        return Err(scope::unreadable(
            "commit receipt",
            "stored writer/durability differs from the actual receipt",
        ));
    }
    Ok(event)
}
fn key(receipt: &CommitReceipt) -> Result<IdempotencyKey> {
    receipt
        .request_key
        .clone()
        .ok_or_else(|| scope::unreadable("commit receipt", "keyed operation has no request key"))
}
pub(crate) fn write_fields(receipt: &CommitReceipt, event: &StoredEvent) -> Result<WriteReceipt> {
    if event.header.event != receipt.primary_event
        || !receipt.events.contains(&receipt.primary_event)
        || event.writer.kind() != receipt.writer.kind()
        || event.durability != receipt.durability
    {
        return Err(scope::unreadable(
            "write receipt",
            "immutable primary event or writer differs from its actual completion",
        ));
    }
    Ok(WriteReceipt {
        state: commit_state(receipt),
        event_id: receipt.primary_event.clone(),
        recorded_at: timestamp(event.recorded_at_us)?,
        idempotency_key: key(receipt)?,
        writer: writer(receipt),
    })
}
pub(crate) fn named_project<R: Snapshot>(
    cx: &mut commit::Cx<'_, R>,
) -> Result<Named<se_types::ProjectId>> {
    let id = scope::project(cx.admission)?;
    let record = scope::require_present(
        cx.read
            .project(id.clone())
            .map_err(|error| store_error(&error))?,
        "receipt project",
        "Verify the event's recorded project in this data home; when completing a write, preserve its original request key and event IDs.",
    )?;
    let name = match &record.current.body {
        EventBody::ProjectRegistered { name, .. }
        | EventBody::ProjectUpdated { name, .. }
        | EventBody::ProjectMoved { name, .. } => name.clone(),
        _ => match record.original.as_deref().map(|event| &event.body) {
            Some(EventBody::ProjectRegistered { name, .. }) => name.clone(),
            _ => {
                return Err(scope::unreadable(
                    "receipt project",
                    "named project registration is unavailable",
                ));
            }
        },
    };
    Ok(Named { id, name })
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn message<R: Snapshot>(
    output: commit::MessageSendOutput,
    cx: &mut commit::Cx<'_, R>,
) -> Result<MessageOutput> {
    let event = committed_event(cx.read, &output.commit)?;
    let project = scope::project(cx.admission)?;
    let record = scope::require_present(
        cx.read
            .project(project.clone())
            .map_err(|e| store_error(&e))?,
        "receipt project",
        "Verify the event's recorded project in this data home; when completing a write, preserve its original request key and event IDs.",
    )?;
    let project_name = match record.current.body {
        EventBody::ProjectRegistered { name, .. }
        | EventBody::ProjectUpdated { name, .. }
        | EventBody::ProjectMoved { name, .. } => name,
        _ => {
            return Err(scope::unreadable(
                "message project",
                "current registration is not active",
            ));
        }
    };
    let (message, recipient, work, kind, body, refs, reply_to) = match event.body {
        EventBody::MessageSent {
            message,
            recipient,
            kind,
            body,
            refs,
            reply_to,
            ..
        } => (message, Some(recipient), None, kind, body, refs, reply_to),
        EventBody::WorkMessageSent {
            message,
            work,
            kind,
            body,
            refs,
            reply_to,
            ..
        } => (message, None, Some(work), kind, body, refs, reply_to),
        _ => {
            return Err(scope::unreadable(
                "message receipt",
                "stored primary event/message differs",
            ));
        }
    };
    if message != output.message {
        return Err(scope::unreadable(
            "message receipt",
            "stored primary event/message differs",
        ));
    }
    let StoredText::Present(body) = body else {
        return Err(scope::unreadable(
            "committed message body",
            "content was erased; the original body digest cannot be reconstructed",
        ));
    };
    let kind = serde_json::from_value(serde_json::Value::String(kind))
        .map_err(|e| scope::unreadable("stored message kind", &e.to_string()))?;
    let record = scope::require_present(
        cx.read
            .message(message.clone())
            .map_err(|e| store_error(&e))?,
        "message notification",
        "Inspect the original message with its original key; do not send another message.",
    )?;
    let from = mail_sender_ref(cx.read, &record)?;
    let notification = notification(cx.read, record.quiet, record.notifications)?;
    Ok(MessageOutput {
        state: commit_state(&output.commit),
        message_id: message,
        event_id: output.commit.primary_event.clone(),
        recorded_at: timestamp(event.recorded_at_us)?,
        project: Named {
            id: project,
            name: project_name,
        },
        from,
        to: match &recipient {
            Some(recipient) => actor_ref(cx.read, recipient)?,
            None => floor_ref(),
        },
        work,
        kind,
        reply_to,
        refs,
        idempotency_key: key(&output.commit)?,
        body: BodyDigest {
            bytes: body.len() as u64,
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
        },
        delivery: Delivery {
            state: if matches!(recipient, Some(Actor::Human(_))) {
                "not-applicable"
            } else {
                "pending"
            }
            .into(),
            at: None,
        },
        writer: writer(&output.commit),
        notification,
    })
}

pub fn working_state<R: Snapshot>(
    output: commit::WorkingStateSetOutput,
    cx: &mut commit::Cx<'_, R>,
) -> Result<WorkingStateReceipt> {
    let event = committed_event(cx.read, &output.commit)?;
    if !matches!(&event.body,EventBody::WorkingStateSet {agent,..} if agent==&output.agent) {
        return Err(scope::unreadable(
            "working-state receipt",
            "stored primary event/agent differs",
        ));
    }
    let head = scope::require_present(
        cx.read
            .working_state(output.agent.clone())
            .map_err(|e| store_error(&e))?,
        "current working state",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    if head.revision.value < event.revision.value {
        return Err(scope::unreadable(
            "working-state receipt",
            "fresh continuation snapshot predates the committed entity revision",
        ));
    }
    Ok(WorkingStateReceipt {
        agent: named_agent(cx.read, &output.agent)?,
        state: commit_state(&output.commit),
        revision: event.revision.value.get(),
        current_revision: head.revision.value.get(),
        event_id: output.commit.primary_event.clone(),
        idempotency_key: key(&output.commit)?,
        writer: writer(&output.commit),
    })
}
pub fn working_state_get<R: Snapshot>(
    agent: AgentId,
    cx: &mut commit::Cx<'_, R>,
) -> Result<WorkingStateOutput> {
    let name = named_agent(cx.read, &agent)?;
    let value = match cx.read.working_state(agent).map_err(|e| store_error(&e))? {
        Read::Present { value } => {
            let updated_at = timestamp(event_time(&value.current))?;
            match value.current.body {
                EventBody::WorkingStateSet {
                    text: StoredText::Present(text),
                    ..
                } => Read::Present {
                    value: WorkingStateValue {
                        text,
                        revision: value.revision.value.get(),
                        recorded_at: updated_at,
                    },
                },
                EventBody::WorkingStateSet {
                    text: StoredText::Erased { .. },
                    ..
                } => {
                    return Err(scope::unreadable(
                        "working state",
                        "stored content was erased",
                    ));
                }
                _ => {
                    return Err(scope::unreadable(
                        "working-state projection",
                        "current event has another kind",
                    ));
                }
            }
        }
        Read::Absent { checked } => Read::Absent { checked },
        Read::Unknown { what } => Read::Unknown { what },
        Read::Unreadable {
            source,
            reason,
            error,
        } => Read::Unreadable {
            source,
            reason,
            error,
        },
    };
    Ok(WorkingStateOutput { agent: name, value })
}

/// Shared CLI/MCP wire projection; resolving actor names never changes marks.
pub fn notification<R: Snapshot>(
    read: &mut R,
    quiet: bool,
    records: Vec<se_store::NotificationRecord>,
) -> Result<Notification> {
    let recipients = records
        .into_iter()
        .map(|record| {
            Ok(NotificationRecipient {
                recipient: actor_ref(read, &record.recipient)?,
                state: record.state,
                event_id: record.event,
                at: record.recorded_at_us.map(timestamp).transpose()?,
                code: record.code,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Notification {
        intent: if quiet { "quiet" } else { "notify" }.into(),
        recipients,
    })
}
