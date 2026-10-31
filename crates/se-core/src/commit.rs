//! Synchronous commit bridge for the first two write operations.
//! AtomicBatch and Snapshot belong to se-store; se-types never depends on se-store.
use se_store::{Admission, AtomicBatch, CommitReceipt, Snapshot};
use se_types::{AgentId, IdempotencyKey, MessageId, Result};

/// Borrowed finite read transaction. A plan must release this before host await.
/// Admission is supplied by verified host/CLI policy, never decoded from a DTO.
pub struct Cx<'a, R: Snapshot> {
    pub read: &'a mut R,
    pub admission: &'a Admission,
}

/// Future custody operations select their own typed plan; these two writes have none.
pub enum NoCustody {}

/// Owned values only. Commit continuations hold no read lease, SQL handle or closure.
#[allow(
    clippy::large_enum_variant,
    reason = "Preserve the agreed by-value AtomicBatch handoff without per-write boxing."
)]
pub enum OpStep<O, T, P = NoCustody> {
    Complete(O),
    Commit { batch: AtomicBatch, then: T },
    Custody(P),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    #[default]
    Note,
    Task,
    Question,
    Answer,
    Blocker,
    Done,
    Handoff,
    Finding,
}

/// One closed DTO for CLI, MCP, IPC and linked message.send; Validate enforces 50's bounds.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageSend {
    pub to: String,
    pub body: String,
    #[serde(default)]
    pub kind: MessageKind,
    #[serde(default)]
    pub refs: Vec<String>,
    pub reply_to: Option<MessageId>,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AbsentRevision {
    Absent,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ExpectedRevision {
    Revision(u64),
    Absent(AbsentRevision),
}

/// Owner selectors are typed CLI metadata and cannot occur in the bound MCP schema.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkingStateSet {
    pub text: String,
    pub expect: ExpectedRevision,
    pub idempotency_key: IdempotencyKey,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<AgentId>,
}

/// Constructed by the future kernel planner from the admitted request and allocated IDs.
/// The original receipt resolves replay; allocated IDs never enter its semantic fingerprint.
pub struct MessageSendThen {
    pub(crate) request: IdempotencyKey,
}
pub struct WorkingStateSetThen {
    pub(crate) request: IdempotencyKey,
    pub(crate) agent: AgentId,
}

/// Store CommitReceipt is the only writer/event/deduplication source.
pub struct MessageSendOutput {
    pub message: MessageId,
    pub commit: CommitReceipt,
}
pub struct WorkingStateSetOutput {
    pub agent: AgentId,
    pub commit: CommitReceipt,
}

/// Synchronous declarations only: the host runs planning and finish in bounded
/// blocking-pool jobs, with owned/Arc readers and no Snapshot across an await.
/// Planner validation precedes any submission;
/// both finish methods consume the actual receipt from the same transaction engine.
/// Finish uses a fresh finite read at/after the receipt to resolve actual committed
/// payload IDs on replay, never the newly allocated draft IDs. It cannot write.
/// A commit failure/unknown outcome returns an error instead of invoking finish.
pub trait CoreOps: Send + Sync {
    fn message_send<R: Snapshot>(
        &self,
        input: MessageSend,
        cx: &mut Cx<'_, R>,
    ) -> Result<OpStep<MessageSendOutput, MessageSendThen>>;
    fn message_committed<R: Snapshot>(
        &self,
        then: MessageSendThen,
        receipt: CommitReceipt,
        cx: &mut Cx<'_, R>,
    ) -> Result<MessageSendOutput>;
    fn working_state_set<R: Snapshot>(
        &self,
        input: WorkingStateSet,
        cx: &mut Cx<'_, R>,
    ) -> Result<OpStep<WorkingStateSetOutput, WorkingStateSetThen>>;
    fn working_state_committed<R: Snapshot>(
        &self,
        then: WorkingStateSetThen,
        receipt: CommitReceipt,
        cx: &mut Cx<'_, R>,
    ) -> Result<WorkingStateSetOutput>;
}
