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
pub fn actor_ref<R: Snapshot>(read: &mut R, actor: &Actor) -> Result<ActorRef> {
    let record = scope::require_present(
        read.principal(actor.clone()).map_err(|e| store_error(&e))?,
        "receipt principal",
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
        }
        .into(),
        id: scope::actor_id(actor),
        name,
    })
}
pub fn named_agent<R: Snapshot>(read: &mut R, agent: &AgentId) -> Result<Named<AgentId>> {
    let actor = actor_ref(read, &Actor::Agent(agent.clone()))?;
    Ok(Named {
        id: agent.clone(),
        name: actor.name,
    })
}
fn committed_event<R: Snapshot>(read: &mut R, receipt: &CommitReceipt) -> Result<StoredEvent> {
    let event = scope::require_present(
        read.event(receipt.primary_event.clone())
            .map_err(|e| store_error(&e))?,
        "receipt primary event",
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
    )?;
    let project_name = match record.current.body {
        EventBody::ProjectRegistered { name, .. } | EventBody::ProjectUpdated { name, .. } => name,
        _ => {
            return Err(scope::unreadable(
                "message project",
                "current registration is not active",
            ));
        }
    };
    match event.body {
        EventBody::MessageSent {
            message,
            recipient,
            kind,
            body,
            refs,
            reply_to,
        } if message == output.message => {
            let StoredText::Present(body) = body else {
                return Err(scope::unreadable(
                    "committed message body",
                    "content was erased; the original body digest cannot be reconstructed",
                ));
            };
            let kind = serde_json::from_value(serde_json::Value::String(kind))
                .map_err(|e| scope::unreadable("stored message kind", &e.to_string()))?;
            Ok(MessageOutput {
                state: commit_state(&output.commit),
                message_id: message,
                event_id: output.commit.primary_event.clone(),
                recorded_at: timestamp(event.recorded_at_us)?,
                project: Named {
                    id: project,
                    name: project_name,
                },
                from: actor_ref(cx.read, &event.header.actor)?,
                to: actor_ref(cx.read, &recipient)?,
                kind,
                reply_to,
                refs,
                idempotency_key: key(&output.commit)?,
                body: BodyDigest {
                    bytes: body.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
                },
                delivery: Delivery {
                    state: if matches!(recipient, Actor::Human(_)) {
                        "not-applicable"
                    } else {
                        "pending"
                    }
                    .into(),
                    at: None,
                },
                writer: writer(&output.commit),
            })
        }
        _ => Err(scope::unreadable(
            "message receipt",
            "stored primary event/message differs",
        )),
    }
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
        Read::Present { value } => match value.current.body {
            EventBody::WorkingStateSet {
                text: StoredText::Present(text),
                ..
            } => Read::Present {
                value: WorkingStateValue {
                    text,
                    revision: value.revision.value.get(),
                    recorded_at: timestamp(value.current.recorded_at_us)?,
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
        },
        other => other.map(|_| unreachable!()),
    };
    Ok(WorkingStateOutput { agent: name, value })
}
