//! Full reads and attributable recipient marks. Budget admission precedes any
//! marker batch; listing and inspection of another recipient never mark read.
use super::{AnyOutput, inputs::Validate, outputs::*, receipt};
use crate::{
    commit::{Cx, OpStep},
    dispatch::Kernel,
    scope,
    store_error::store_error,
};
use schemars::JsonSchema;
use se_store::{Actor, CommitReceipt, EventBody, MessageRecord, Snapshot, StoredText};
use se_types::{EventId, IdempotencyKey, MessageId, Read, Result, SeError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
fn default_budget() -> u32 {
    262144
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageRead {
    pub msg_id: MessageId,
    #[serde(default = "default_budget")]
    pub budget: u32,
}
impl Validate for MessageRead {
    fn validate(&self) -> Result<()> {
        if !(512..=1048576).contains(&self.budget) {
            return Err(SeError::invalid(
                "message read budget",
                "512..1048576 serialized output bytes",
            ));
        }
        Ok(())
    }
}
macro_rules! mark_input {
    ($name:ident) => {
        #[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub msg_id: MessageId,
        }
        impl Validate for $name {
            fn validate(&self) -> Result<()> {
                Ok(())
            }
        }
    };
}
mark_input!(MessageAck);
mark_input!(MessageDismiss);
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DispositionReceipt {
    pub message_id: MessageId,
    pub disposition: String,
    pub marker: MarkerState,
    pub by: ActorRef,
    pub state: CommitState,
    pub request_identity: MarkerIdentity,
    pub event_id: EventId,
    pub recorded_at: String,
    pub writer: Writer,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MarkerState {
    New,
    Already,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum MarkerIdentity {
    Natural {
        recipient: String,
        message_id: MessageId,
        marker: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageReadOutput {
    pub message: MessageRow,
    pub marked_read: bool,
    pub inspection: bool,
    /// Inspection has no write fields. Recipient reads expose the original
    /// immutable marker receipt at the same top level as every write family.
    #[serde(flatten)]
    pub receipt: Option<DispositionReceipt>,
}
#[derive(Clone, Copy)]
pub enum Mark {
    Read,
    Dismiss,
}
pub struct MarkThen {
    key: IdempotencyKey,
    message: MessageId,
    mark: Mark,
    body_budget: Option<u32>,
    replayed: bool,
}
fn selected<S: Snapshot>(cx: &mut Cx<'_, S>, id: MessageId) -> Result<MessageRecord> {
    scope::project(cx.admission)?;
    scope::require_present(
        cx.read.message(id).map_err(|error| store_error(&error))?,
        "message",
        "Use a message ID from your authorized inbox or sent history",
    )
}
fn row<S: Snapshot>(cx: &mut Cx<'_, S>, record: MessageRecord) -> Result<MessageRow> {
    let StoredText::Present(body) = record.body else {
        return Err(scope::unreadable(
            "message body",
            "body is erased; no read mark was inferred",
        ));
    };
    if !record.body_complete {
        return Err(scope::unreadable(
            "message body",
            "complete body was not available within the store read bound; no read mark was inferred",
        ));
    }
    let event = scope::require_present(
        cx.read
            .event(record.event.clone())
            .map_err(|error| store_error(&error))?,
        "message sent event",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    Ok(MessageRow {
        id: record.message,
        event_id: record.event,
        from: receipt::actor_ref(cx.read, &record.sender)?,
        to: if record.work.is_some() {
            receipt::floor_ref()
        } else {
            receipt::actor_ref(cx.read, &record.recipient)?
        },
        for_recipient: if record.work.is_some() {
            Some(receipt::actor_ref(cx.read, &record.recipient)?)
        } else {
            None
        },
        work: record.work,
        kind: serde_json::from_value(serde_json::Value::String(record.kind))
            .map_err(|error| scope::unreadable("message kind", &error.to_string()))?,
        sent_at: receipt::timestamp(event.recorded_at_us)?,
        reply_to: record.reply_to,
        refs: record.refs,
        delivery: Delivery {
            state: if matches!(record.recipient, Actor::Human(_)) {
                "not-applicable"
            } else if record.delivered.is_some() {
                "delivered"
            } else {
                "pending"
            }
            .into(),
            at: None,
        },
        disposition: Delivery {
            state: if record.dismissed.is_some() {
                "dismissed"
            } else if record.read.is_some() {
                "read"
            } else {
                "unread"
            }
            .into(),
            at: None,
        },
        notification: receipt::notification(cx.read, record.quiet, record.notifications)?,
        body: MessageBody {
            bytes: body.len() as u64,
            text: body,
            complete: true,
            command: None,
            argv: None,
        },
        unreadable: None,
    })
}
fn fits(output: &AnyOutput, budget: u32) -> Result<()> {
    let bytes = serde_json::to_vec(output)
        .map_err(|error| scope::unreadable("complete message response", &error.to_string()))?;
    if bytes.len() > budget as usize {
        return Err(SeError::too_large(
            "complete message read response; use a larger CLI --budget or explicitly ack without a body",
            budget as usize,
            bytes.len(),
        ));
    }
    Ok(())
}
pub fn read<S: Snapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    input: MessageRead,
) -> Result<OpStep<AnyOutput, MarkThen>> {
    input.validate()?;
    let record = selected(cx, input.msg_id.clone())?;
    let recipient = record.recipient == cx.admission.actor;
    let mut message = row(cx, record)?;
    let mut marker = if recipient {
        Some(DispositionReceipt {
            message_id: input.msg_id.clone(),
            disposition: "read".into(),
            marker: MarkerState::Already,
            by: receipt::actor_ref(cx.read, &cx.admission.actor)?,
            state: CommitState::Committed,
            request_identity: MarkerIdentity::Natural {
                recipient: scope::actor_id(&cx.admission.actor),
                message_id: input.msg_id.clone(),
                marker: "read".into(),
            },
            event_id: kernel.facts()?.event.clone(),
            recorded_at: "0".repeat(64),
            writer: Writer::Host {
                host_generation: u64::MAX.to_string(),
            },
        })
    } else {
        None
    };
    if recipient {
        message.disposition.state = "dismissed".into();
        message.disposition.at = Some("0".repeat(64));
        // Legal principal names are at most 64 ASCII bytes. Reserve their
        // maximum escaped representation across a concurrent rename, plus
        // the optional host diagnostics, before committing a read marker.
        message.from.name = "\0".repeat(message.from.name.len().max(64));
        message.to.name = "\0".repeat(message.to.name.len().max(64));
        if let Some(marker) = &mut marker {
            marker.by.name = "\0".repeat(marker.by.name.len().max(64));
        }
    }
    let mut prospective: AnyOutput = MessageReadOutput {
        message,
        marked_read: recipient,
        inspection: !recipient,
        receipt: marker,
    }
    .into();
    if recipient {
        prospective = prospective.with_write_timings(ReceiptWriteTimings {
            queue_ms: f64::MAX,
            transaction_ms: f64::MAX,
            commit_call_ms: f64::MAX,
            checkpoint_ms: Some(f64::MAX),
            durability: WriteDurability::Normal,
        });
    }
    fits(&prospective, input.budget)?;
    if !recipient {
        return Ok(OpStep::Complete(prospective));
    }
    plan(kernel, cx, input.msg_id, Mark::Read, Some(input.budget))
}
pub fn plan<S: Snapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    id: MessageId,
    mark: Mark,
    body_budget: Option<u32>,
) -> Result<OpStep<AnyOutput, MarkThen>> {
    let record = selected(cx, id.clone())?;
    if record.recipient != cx.admission.actor {
        return Err(SeError::invalid(
            "message disposition",
            "the actual recipient; owner inspection cannot acknowledge another agent's mail",
        ));
    }
    let tag = match mark {
        Mark::Read => "read",
        Mark::Dismiss => "dismissed",
    };
    let key = IdempotencyKey::new(format!(
        "message.mark.{}",
        se_types::hex_lower(&Sha256::digest(
            serde_json::to_vec(&(scope::project(cx.admission)?, &cx.admission.actor, &id, tag))
                .map_err(|error| scope::unreadable(
                    "message disposition identity",
                    &error.to_string()
                ))?
        ))
    ))?;
    let mut then = MarkThen {
        key: key.clone(),
        message: id.clone(),
        mark,
        body_budget,
        replayed: false,
    };
    match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => {
            then.replayed = true;
            return committed(cx, then, value).map(OpStep::Complete);
        }
        Read::Absent { .. } => (),
        Read::Unknown { what } => {
            return Err(scope::unreadable("message marker reconciliation", &what));
        }
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
    }
    let event = kernel.event(
        match mark {
            Mark::Read => EventBody::MessageRead {
                message: id.clone(),
                recipient: cx.admission.actor.clone(),
            },
            Mark::Dismiss => EventBody::MessageDismissed {
                message: id.clone(),
                recipient: cx.admission.actor.clone(),
            },
        },
        cx,
    )?;
    let batch = kernel.batch(
        "message.recipient_mark",
        key,
        serde_json::json!({"message":id,"disposition":tag}),
        event,
        cx,
    )?;
    Ok(OpStep::Commit { batch, then })
}
pub fn committed<S: Snapshot>(
    cx: &mut Cx<'_, S>,
    then: MarkThen,
    receipt: CommitReceipt,
) -> Result<AnyOutput> {
    receipt::receipt_key(&receipt, &then.key, "message disposition completion")?;
    let event = receipt::committed_event(cx.read, &receipt)?;
    let (message, recipient, tag) = match (&then.mark, &event.body) {
        (Mark::Read, EventBody::MessageRead { message, recipient }) => (message, recipient, "read"),
        (Mark::Dismiss, EventBody::MessageDismissed { message, recipient }) => {
            (message, recipient, "dismissed")
        }
        _ => {
            return Err(scope::unreadable(
                "message disposition receipt",
                "receipt is not the requested original recipient mark",
            ));
        }
    };
    if message != &then.message || recipient != &cx.admission.actor {
        return Err(SeError::invalid(
            "message disposition receipt",
            "the original message and actual recipient",
        ));
    }
    let replayed = then.replayed || !matches!(receipt.state, se_store::CommitState::Committed);
    let marker = DispositionReceipt {
        message_id: message.clone(),
        disposition: tag.into(),
        marker: if replayed {
            MarkerState::Already
        } else {
            MarkerState::New
        },
        by: receipt::actor_ref(cx.read, recipient)?,
        state: if replayed {
            CommitState::Replayed
        } else {
            CommitState::Committed
        },
        request_identity: MarkerIdentity::Natural {
            recipient: scope::actor_id(recipient),
            message_id: message.clone(),
            marker: tag.into(),
        },
        event_id: event.header.event,
        recorded_at: receipt::timestamp(event.recorded_at_us)?,
        writer: receipt::writer(&receipt),
    };
    if let Some(budget) = then.body_budget {
        let record = selected(cx, then.message)?;
        let output: AnyOutput = MessageReadOutput {
            message: row(cx, record)?,
            marked_read: true,
            inspection: false,
            receipt: Some(marker),
        }
        .into();
        fits(&output, budget)?;
        Ok(output)
    } else {
        Ok(marker.into())
    }
}
