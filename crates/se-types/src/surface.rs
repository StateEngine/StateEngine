//! Public receipt values shared by CLI, IPC and linked consumers. No effects or authority.
use crate::{EventId, IdempotencyKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub const ACP_NO_SANDBOX_NOTICE: &str =
    "This harness provides no execution sandbox in protocol mode.";
mod agent;
mod decision;
pub use agent::*;
pub use decision::*;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Named<I> {
    pub id: I,
    pub name: String,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Claude,
    Codex,
    SeCode,
    Acp,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Writer {
    Direct,
    Host { host_generation: String },
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CommitState {
    Committed,
    Replayed,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ActorRef {
    pub kind: String,
    pub id: String,
    pub name: String,
}
/// Immutable original commit fields. A replay retains these values and changes
/// only state; transient measurements remain in core's outer diagnostics.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WriteReceipt {
    pub state: CommitState,
    pub event_id: EventId,
    pub recorded_at: String,
    pub idempotency_key: IdempotencyKey,
    pub writer: Writer,
}
/// A disclosed mistake/drift guard result, never authority supplied by wire data.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptAuthority {
    pub guard: Option<ReceiptGuard>,
    pub limit: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
pub enum ReceiptGuard {
    #[serde(rename = "owner-terminal-outside-agent-tree")]
    OwnerTerminalOutsideAgentTree,
}
