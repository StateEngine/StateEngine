use super::{ActorRef, CommitState, Named, Writer};
use crate::commit::MessageKind;
use schemars::JsonSchema;
use se_types::{AgentId, EventId, IdempotencyKey, MessageId, Page, ProjectId, Read};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BodyDigest {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Delivery {
    pub state: String,
    pub at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageOutput {
    pub state: CommitState,
    pub message_id: MessageId,
    pub event_id: EventId,
    pub recorded_at: String,
    pub project: Named<ProjectId>,
    pub from: ActorRef,
    pub to: ActorRef,
    pub kind: MessageKind,
    pub reply_to: Option<MessageId>,
    pub refs: Vec<EventId>,
    pub idempotency_key: IdempotencyKey,
    pub body: BodyDigest,
    pub delivery: Delivery,
    pub writer: Writer,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WorkingStateValue {
    pub text: String,
    pub revision: u64,
    #[serde(rename = "updated_at")]
    pub recorded_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WorkingStateOutput {
    pub agent: Named<AgentId>,
    pub value: Read<WorkingStateValue>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WorkingStateReceipt {
    pub agent: Named<AgentId>,
    pub state: CommitState,
    pub revision: u64,
    pub current_revision: u64,
    pub event_id: EventId,
    pub idempotency_key: IdempotencyKey,
    pub writer: Writer,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageBody {
    pub text: String,
    pub complete: bool,
    pub bytes: u64,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageRow {
    pub id: MessageId,
    pub event_id: EventId,
    pub from: ActorRef,
    pub to: ActorRef,
    pub kind: MessageKind,
    pub sent_at: String,
    pub reply_to: Option<MessageId>,
    pub refs: Vec<EventId>,
    pub delivery: Delivery,
    pub disposition: Delivery,
    pub body: MessageBody,
    pub unreadable: Option<UnreadableRow>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UnreadableRow {
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageFilter {
    pub to: Option<ActorRef>,
    pub from: Option<ActorRef>,
    pub kind: Option<MessageKind>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessagePageView {
    pub op: String,
    pub recipient: Option<ActorRef>,
    pub disposition: String,
    pub r#box: String,
    pub filter: MessageFilter,
    pub inspection: bool,
    pub full: bool,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessagePage {
    pub view: MessagePageView,
    pub consistency: String,
    #[serde(flatten)]
    pub page: Page<MessageRow>,
    pub unread_total: Option<u64>,
}
