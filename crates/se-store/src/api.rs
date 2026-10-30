use crate::*;
use se_types::{
    AgentId, DecisionId, EventId, IdempotencyKey, LifecycleId, MessageId, Page, ProjectId, Read,
    SessionId,
};
use std::{future::Future, io::Read as ByteReader, sync::Arc, time::Duration};

/// Host filesystem custody supplies the held per-user runtime lease. An in-process
/// caller is trusted; IPC callers cannot construct this object from request JSON.
pub trait RuntimeLease: Send + Sync {
    fn identity(&self) -> StoreResult<LeaseIdentity>;
}
/// Constructors are declarations, not executable fallback/default implementations.
pub trait StoreFactory {
    type Reader: ReadStore;
    type Direct: DirectStore;
    type Host: HostStore;
    /// Whole-copy stable read transaction; WAL pressure cancels backup, not writes.
    fn backup(
        options: &StoreOptions,
        lease: Arc<dyn RuntimeLease>,
        context: BackupContext,
        deadline: Duration,
    ) -> StoreResult<BackupReport>;
    /// Read-only inventory before owner approval or writer drain; recheck on erase.
    fn erasure_plan(
        options: &StoreOptions,
        targets: Vec<EraseTarget>,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<ErasurePlan>;
    /// Inspect owned automatic generations even when the live store is corrupt.
    fn inspect_backups(
        options: &StoreOptions,
        budget: ReadBudget,
    ) -> StoreResult<Page<Read<BackupGeneration>>>;
    /// Owner restore only: recheck newest valid generation and retain source/WAL.
    fn restore_backup(
        options: &StoreOptions,
        backup: BackupGeneration,
        target_store: StoreId,
        admission: &Admission,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Self::Host>;
    fn open_reader(options: &StoreOptions) -> StoreResult<Read<Self::Reader>>;
    fn open_direct(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Read<Self::Direct>>;
    /// Supported additive migrations finish automatically under exclusive custody
    /// after verified backup; an older schema never escapes as a HostStore.
    fn open_host(options: &StoreOptions, lease: &dyn RuntimeLease)
    -> StoreResult<Read<Self::Host>>;
    /// Owner bootstrap with shared runtime lease; publish a new schema no-replace.
    fn create_direct(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
        store_id: StoreId,
    ) -> StoreResult<Self::Direct>;
    fn create(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
        store_id: StoreId,
    ) -> StoreResult<Self::Host>;
}
pub trait ReadStore {
    type Snapshot: Snapshot;
    fn info(&self) -> StoreResult<StoreInfo>;
    /// Non-secret owner/fence view; never returns the private owning event.
    fn runtime_owner(&self) -> StoreResult<Read<RuntimeOwnerHead>>;
    fn inspect_backups(&self, budget: ReadBudget) -> StoreResult<Page<Read<BackupGeneration>>>;
    fn snapshot(&self, scope: ReadScope) -> StoreResult<Self::Snapshot>;
    /// Bootstrap-only hash lookup used by the trusted capability verifier before
    /// constructing Admission; never an operation/tool or a principal fallback.
    fn credential(&self, secret_sha256: [u8; 32]) -> StoreResult<Read<CredentialRecord>>;
}
pub trait TextStaging {
    fn stage_text(
        &self,
        source: &mut dyn ByteReader,
        maximum_bytes: u64,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<StagedText>;
}
/// Synchronous hostless route; returns the canonical engine receipt directly.
pub trait DirectStore: ReadStore + TextStaging {
    fn append(
        &mut self,
        batch: AtomicBatch,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CommitReceipt>;
    fn close(self) -> StoreResult<()>
    where
        Self: Sized;
}
pub trait HostStore: ReadStore + TextStaging + Sized {
    type Writer: WriterOwner<Host = Self>;
    /// Trusted maintenance point read of a runtime.* fact, including private nonce.
    /// Public snapshots/history/search/export must never expose these kinds.
    fn runtime_ownership_fact(&self, event: EventId) -> StoreResult<Read<StoredEvent>>;
    /// Same coordination context before/after the writer ownership transfer.
    fn backup_context(&self) -> BackupContext;
    fn start_writer(
        self,
        options: WriterOptions,
        lease: Arc<dyn RuntimeLease>,
    ) -> StoreResult<Self::Writer>;
    /// Exclusive maintenance only; one ownership event, canonical FULL commit.
    fn record_runtime_ownership(
        &mut self,
        batch: AtomicBatch,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CommitReceipt>;
    fn checkpoint(
        &mut self,
        mode: CheckpointMode,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CheckpointReport>;
    fn erase(
        &mut self,
        plan: ErasurePlan,
        approval: ErasureApproval,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<ErasureReport>;
    fn close_clean(self, lease: &dyn RuntimeLease, deadline: Duration) -> StoreResult<BackupReport>
    where
        Self: Sized;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointMode {
    Passive,
    Truncate,
}
pub trait WriterOwner {
    type Host: HostStore;
    type Client: WriterClient;
    fn client(&self) -> Self::Client;
    /// Clone shared state without a writer barrier or a new worker.
    fn backup_context(&self) -> BackupContext;
    type Flush: Future<Output = StoreResult<FlushReport>> + Send;
    type Drain: Future<Output = StoreResult<DrainedHost<Self::Host>>> + Send;
    fn flush(&mut self, deadline: Duration) -> StoreResult<Self::Flush>;
    fn drain(self, deadline: Duration) -> Self::Drain
    where
        Self: Sized;
}
pub struct DrainedHost<H: HostStore> {
    pub host: H,
    pub report: FlushReport,
}
/// Host route: obtained from HostStore::start_writer -> WriterOwner::client.
/// Submit never waits for COMMIT; host async task awaits the returned CommitWait.
pub trait WriterClient: Clone + Send + Sync {
    type Completion: CommitWait;
    fn submit(&self, batch: AtomicBatch) -> StoreResult<Self::Completion>;
}
/// Await-only host completion. DirectStore::append returns CommitReceipt synchronously.
pub trait CommitWait: Future<Output = StoreResult<CommitReceipt>> + Send {}
/// Private implementation seam: both host group commit and direct append use
/// this exact transaction engine. SQL handles never appear in the public API.
#[allow(
    dead_code,
    reason = "Compile-only private transaction contract; implementation is not admitted."
)]
pub(crate) trait TransactionEngine {
    fn commit_group(
        &mut self,
        batches: Vec<AtomicBatch>,
    ) -> StoreResult<Vec<StoreResult<CommitReceipt>>>;
    fn append_atomic(&mut self, batch: AtomicBatch) -> StoreResult<PreparedReceipt>;
    fn apply(&mut self, event: &StoredEvent) -> StoreResult<()>;
}
/// Cannot be returned to a caller as a durable receipt before group COMMIT.
pub(crate) struct PreparedReceipt {
    _private: (),
}

#[derive(Clone, Debug)]
pub struct MessageQuery {
    pub recipient: Option<Actor>,
    pub sender: Option<Actor>,
    pub kind: Option<String>,
    pub unread_only: bool,
    pub full_body: bool,
}
#[derive(Clone, Debug)]
pub struct DecisionQuery {
    pub id: Option<DecisionId>,
    pub pending_only: bool,
    pub history: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryFamily {
    Identity,
    Sessions,
    Messages,
    Decisions,
    Turns,
    Processes,
    WorkingState,
    Cursors,
    Effects,
    Import,
    Recovery,
}
#[derive(Clone, Debug)]
pub struct HistoryQuery {
    pub agent: Option<AgentId>,
    pub session: Option<SessionId>,
    /// Empty means every authorized kind; codec rejects unknown exact names.
    pub kinds: Vec<EventKind>,
    pub families: Vec<HistoryFamily>,
    pub since: Option<Revision>,
}
#[derive(Clone, Debug)]
pub struct SearchQuery {
    pub text: String,
    pub history: HistoryQuery,
}
/// Internal storage record, not a frozen CLI/MCP wire DTO.
#[derive(Clone)]
pub struct MessageRecord {
    pub message: MessageId,
    pub event: EventId,
    pub sent: Revision,
    pub sender: Actor,
    pub recipient: Actor,
    pub kind: String,
    pub body: StoredText,
    pub refs: Vec<EventId>,
    pub reply_to: Option<MessageId>,
    pub delivered: Option<Revision>,
    pub read: Option<Revision>,
    pub dismissed: Option<Revision>,
    pub body_complete: bool,
}
#[derive(Clone, Debug)]
pub struct CredentialRecord {
    pub credential: RecordId,
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
    pub purpose: String,
    pub expires_at_us: i64,
    pub activation_deadline_us: i64,
    pub state: CredentialState,
    pub revision: Revision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialState {
    Prepared,
    Active,
    Revoked,
}
#[derive(Clone)]
pub struct SearchHit {
    pub event: EventId,
    pub revision: Revision,
    pub snippet: StoredText,
    pub body_complete: bool,
}
/// Current-head record; body is reconstructed from the owning immutable event.
#[derive(Clone)]
pub struct ProjectionRecord {
    pub original: Option<Box<StoredEvent>>,
    pub current: StoredEvent,
}
/// One finite read transaction. No method mutates a marker/cursor or repairs data.
pub trait Snapshot {
    type LegacyRegistry<'a>: se_types::LegacyIdRegistry
    where
        Self: 'a;
    /// Bound to this snapshot's admitted project and recorded import sources.
    fn legacy_registry(&self) -> StoreResult<Self::LegacyRegistry<'_>>;
    fn info(&self) -> StoreInfo;
    /// runtime.* facts are private: known excluded IDs return a typed refusal.
    fn event(&mut self, id: EventId) -> StoreResult<Read<StoredEvent>>;
    /// Excludes runtime.* facts, including their native nonces.
    fn history(
        &mut self,
        query: HistoryQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>>;
    /// Excludes runtime.* facts before matching/snippet construction.
    fn search(&mut self, query: SearchQuery, budget: ReadBudget) -> StoreResult<Page<SearchHit>>;
    /// Non-mail mutable lists are labelled live keysets; Page describes this read only.
    fn projects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn project(&mut self, id: ProjectId) -> StoreResult<Read<ProjectionRecord>>;
    fn principals(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn principal(&mut self, id: Actor) -> StoreResult<Read<ProjectionRecord>>;
    fn profile(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>>;
    fn grant(&mut self, principal: Actor, key: GrantKey) -> StoreResult<Read<ProjectionRecord>>;
    fn session(&mut self, id: SessionId) -> StoreResult<Read<ProjectionRecord>>;
    fn sessions(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn message(&mut self, id: MessageId) -> StoreResult<Read<MessageRecord>>;
    fn messages(
        &mut self,
        query: MessageQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>>;
    fn decision(&mut self, id: DecisionId) -> StoreResult<Read<ProjectionRecord>>;
    fn decisions(
        &mut self,
        query: DecisionQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>>;
    fn turns(&mut self, agent: AgentId, budget: ReadBudget) -> StoreResult<Page<StoredEvent>>;
    fn capture_source(&mut self, source: RecordId) -> StoreResult<Read<ProjectionRecord>>;
    fn process(&mut self, id: LifecycleId) -> StoreResult<Read<ProjectionRecord>>;
    /// Internal recorded custody for status/agent control, not a public process.list operation.
    fn processes(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn working_state(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>>;
    fn cursor(&mut self, agent: AgentId, purpose: String) -> StoreResult<Read<CursorRecord>>;
    fn resume_head(&mut self, principal: Actor) -> StoreResult<Read<ResumeHead>>;
    fn pending_effects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn effect(&mut self, id: RecordId) -> StoreResult<Read<ProjectionRecord>>;
    fn integrations(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn operation_receipt(
        &mut self,
        actor: Actor,
        request_key: IdempotencyKey,
    ) -> StoreResult<Read<CommitReceipt>>;
    fn import_progress(
        &mut self,
        import: RecordId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ImportCheckpoint>>;
    fn close(self) -> StoreResult<()>
    where
        Self: Sized;
}
