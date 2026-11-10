use crate::*;
use se_types::{
    AgentId, EventId, IdempotencyKey, LifecycleId, MessageId, Page, ProjectId, Read, SessionId,
};
use std::{future::Future, io::Read as ByteReader, sync::Arc, time::Duration};

/// Host filesystem custody supplies the held per-user runtime lease. An in-process
/// caller is trusted; IPC callers cannot construct this object from request JSON.
pub trait RuntimeLease: Send + Sync {
    fn identity(&self) -> StoreResult<LeaseIdentity>;
    fn files(&self) -> &dyn StateFiles;
}
/// Native adapter owned by se-proc and wired by the CLI/host, never by request JSON.
/// Every path stays in the held per-user state directory. No shell or ambient umask.
pub trait StateFiles: Send + Sync {
    /// Return at most maximum immediate, owned regular files under retained
    /// no-follow directory custody; over-budget and unreadable are errors.
    fn list_owned(
        &self,
        directory: &std::path::Path,
        maximum: usize,
    ) -> StoreResult<Vec<std::path::PathBuf>> {
        let _ = (directory, maximum);
        Err(crate::error::fail(
            StoreErrorCode::BackupFailed,
            "native bounded backup listing is not wired",
        ))
    }
    /// Ensure a fixed descendant directory exists with native owner-only protection.
    /// Validate existing custody without repairing permissions or following links.
    fn prepare_directory(&self, path: &std::path::Path) -> StoreResult<()> {
        let _ = path;
        Err(crate::error::fail(
            StoreErrorCode::BackupFailed,
            "native protected backup directory preparation is not wired",
        ))
    }
    /// Reserve a unique, protected regular staging file in the owned directory.
    /// Read back owner-only mode/ACL and directory custody before returning.
    fn create_staging(&self, directory: &std::path::Path) -> StoreResult<ProtectedStaging>;
    /// Consume fresh empty staging and retire its exact native name before text
    /// is written, retaining the writable anonymous file until its final drop.
    fn retire_empty_staging(&self, staged: ProtectedStaging) -> StoreResult<std::fs::File>;
    /// Open without following links and verify regular-file identity and owner-only
    /// file/directory protection. Missing is Absent; unknown/unreadable is not absence.
    fn readback(&self, path: &std::path::Path) -> StoreResult<Read<std::fs::File>>;
    /// All SQLite/backup handles have been closed. Sync staged data, publish without
    /// replacing any destination, and sync/read back the destination parent/name.
    /// Collision must return AlreadyExists and preserve the winner.
    fn publish_no_replace(
        &self,
        staged: &std::path::Path,
        destination: &std::path::Path,
    ) -> StoreResult<()>;
    /// Compare-and-replace one owned manifest under held no-follow custody.
    /// Stage/sync new bytes, recheck old digest/identity, atomically publish and witness.
    fn replace_owned(
        &self,
        path: &std::path::Path,
        expected_sha256: Option<[u8; 32]>,
        bytes: &[u8],
    ) -> StoreResult<()> {
        let _ = (path, expected_sha256, bytes);
        Err(crate::error::fail(
            StoreErrorCode::BackupFailed,
            "native owned manifest replacement is not wired",
        ))
    }
    /// Unlink only the held owned regular file matching the expected complete digest.
    /// Success includes parent sync and independent absence readback.
    fn remove_owned(&self, path: &std::path::Path, expected_sha256: [u8; 32]) -> StoreResult<()> {
        let _ = (path, expected_sha256);
        Err(crate::error::fail(
            StoreErrorCode::BackupFailed,
            "native owned generation retirement is not wired",
        ))
    }
}
pub struct ProtectedStaging {
    pub path: std::path::PathBuf,
    pub file: std::fs::File,
}
/// Role-bound constructors; opening never initializes missing state.
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
    /// Resolve the published key before selecting a backup or checking new heads.
    /// Return its stored complete original receipt verbatim, with no fresh fields.
    fn recovery_receipt(
        options: &StoreOptions,
        request: &RequestIdentity,
        admission: &Admission,
    ) -> StoreResult<Read<RestoreReceipt>>;
    /// Owner restore only: keyed recovery fact is FULL-staged before publication.
    fn restore_backup(
        options: &StoreOptions,
        backup: BackupGeneration,
        request: &RequestIdentity,
        target_store: StoreId,
        admission: &Admission,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<RestoreOutcome<Self::Host>>;
    fn open_reader(options: &StoreOptions) -> StoreResult<Read<Self::Reader>>;
    fn open_direct(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Read<Self::Direct>>;
    /// Supported additive migrations finish automatically under exclusive custody
    /// after verified backup; an older schema never escapes as a HostStore.
    fn open_host(options: &StoreOptions, lease: &dyn RuntimeLease)
    -> StoreResult<Read<Self::Host>>;
    /// Explicit owner init with shared runtime lease; FULL-publish schema no-replace.
    fn create_direct(
        options: &StoreOptions,
        lease: &dyn RuntimeLease,
        store_id: StoreId,
    ) -> StoreResult<Self::Direct>;
    /// Explicit owner init only; never an embedded open/activation fallback.
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
    /// Trusted bootstrap inventory after protected native file access, before Admission.
    /// Across the whole home; returns only a complete finite result, never a partial page.
    fn owner_guard(
        &self,
        files: &dyn StateFiles,
        budget: ReadBudget,
    ) -> StoreResult<OwnerGuardInventory>;
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
    /// Embedded cold first bind only, before writer startup: registry owner and
    /// project session retain separate admissions/operations but commit FULL
    /// together. Any member failure rolls back both; no ordinary group exposure.
    fn record_first_binding(
        &mut self,
        binding: FirstBinding,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<FirstBindingReceipt>;
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
#[derive(Clone, Debug)]
pub struct MessageQuery {
    pub recipient: Option<Actor>,
    pub sender: Option<Actor>,
    pub kind: Option<String>,
    pub unread_only: bool,
    pub full_body: bool,
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
#[derive(Clone, Copy, Debug, Default)]
pub enum TranscriptFilter {
    #[default]
    All,
    Chat,
    Metadata,
}
#[derive(Clone, Debug)]
pub struct HistoryQuery {
    pub agent: Option<AgentId>,
    pub session: Option<SessionId>,
    /// Empty means every authorized kind; codec rejects unknown exact names.
    pub kinds: Vec<EventKind>,
    pub families: Vec<HistoryFamily>,
    pub transcript: TranscriptFilter,
    pub since: Option<StorePosition>,
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
    pub revision: Revision,
    pub sent: StorePosition,
    pub sender: Actor,
    pub recipient: Actor,
    pub work: Option<se_types::WorkAddressing>,
    pub kind: String,
    pub body: StoredText,
    pub refs: Vec<EventId>,
    pub reply_to: Option<MessageId>,
    pub delivered: Option<StorePosition>,
    pub read: Option<StorePosition>,
    pub dismissed: Option<StorePosition>,
    pub superseded_by: Option<MessageId>,
    pub body_complete: bool,
    pub quiet: bool,
    pub notifications: Vec<NotificationRecord>,
}
/// Advisory wake observations; none imply accepted input or a read marker.
#[derive(Clone, Debug)]
pub struct NotificationRecord {
    pub recipient: Actor,
    pub state: String,
    pub event: Option<EventId>,
    pub recorded_at_us: Option<i64>,
    pub code: Option<String>,
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

/// Text search omits intentionally erased candidates separately from unreadable
/// omissions in the page window. Erasure is not a failed read or a match.
#[derive(Clone)]
pub struct SearchPage {
    pub page: Page<SearchHit>,
    pub erased: u64,
}
impl SearchPage {
    pub fn items(&self) -> &[SearchHit] {
        self.page.items()
    }
    pub fn window(&self) -> &se_types::Window {
        self.page.window()
    }
    pub fn next(&self) -> Option<&se_types::Cursor> {
        self.page.next()
    }
}
/// Current-head record; body is reconstructed from the owning immutable event.
#[derive(Clone)]
pub struct ProjectionRecord {
    pub revision: Revision,
    pub original: Option<Box<StoredEvent>>,
    pub current: StoredEvent,
}
/// A cursor as issued, its head revision, and the acknowledgment that marked
/// it read, if any. Issuance alone is never acknowledgment.
#[derive(Clone, Debug)]
pub struct CursorHead {
    pub record: CursorRecord,
    pub revision: Revision,
    pub acknowledged: Option<CursorAck>,
}
/// The `cursor.acknowledged` event and the consumer evidence it cited.
#[derive(Clone, Debug)]
pub struct CursorAck {
    pub event: EventId,
    pub evidence: EventId,
}
/// A control target's principal, profile, live (prepared/active) sessions and
/// unreleased processes, oldest first. A prepared session counts until it is
/// revoked, so launch failure must revoke its preparation; more than the
/// bound refuses ReadIncomplete instead of omitting one.
/// Never continuity, mail or turns.
#[derive(Clone)]
pub struct ControlTarget {
    pub principal: ProjectionRecord,
    pub profile: Read<ProjectionRecord>,
    pub sessions: Vec<ProjectionRecord>,
    pub processes: Vec<ProjectionRecord>,
    /// Newest session in any state, ended or revoked included.
    pub latest_session: Read<ProjectionRecord>,
    /// Newest session a launch auto-resume may select. A revoked
    /// preparation that never activated (the launch failed before first
    /// use) never shadows an older resumable session.
    pub resume_session: Read<ProjectionRecord>,
    /// Newest process in any state, exited or ownership-released included.
    pub latest_process: Read<ProjectionRecord>,
    /// Every registered root this project moved away from, newest move
    /// first. Move roots are project identity, not private history: the
    /// launch plan needs them to find a resumed provider transcript, which
    /// stays under the slug of the root where it was written.
    pub moved_from_roots: Vec<se_types::NativePath>,
}
/// Exact retained registration selector; active project lists remain separate.
#[derive(Clone, Debug)]
pub enum RemovedProjectQuery {
    Name(String),
    Root(se_types::NativePath),
}
/// One finite read transaction. No method mutates a marker/cursor or repairs data.
pub trait Snapshot {
    type LegacyRegistry<'a>: se_types::LegacyIdRegistry
    where
        Self: 'a;
    /// Bound to this snapshot's admitted project and recorded import sources.
    fn legacy_registry(&self) -> StoreResult<Self::LegacyRegistry<'_>>;
    fn channel_reply_route(
        &mut self,
        _message: &MessageId,
    ) -> StoreResult<Option<channel::ReplyRoute>> {
        crate::error::later("channel reply route")
    }
    fn channel_active(&mut self) -> StoreResult<Vec<channel::Connection>> {
        crate::error::later("active channels")
    }
    fn channel_update_handled(
        &mut self,
        _id: &channel::ChannelId,
        _update: i64,
    ) -> StoreResult<bool> {
        crate::error::later("provider update disposition")
    }
    fn channel_version(&mut self) -> StoreResult<channel::Version> {
        crate::error::later("channel snapshot version")
    }
    fn channel_connection(
        &mut self,
        _id: &channel::ChannelId,
    ) -> StoreResult<Read<channel::Connection>> {
        crate::error::later("channel point read")
    }
    fn channel_connections(
        &mut self,
        _after: u64,
    ) -> StoreResult<channel::ChannelRows<channel::Connection>> {
        crate::error::later("channel list")
    }
    fn channel_receipt(
        &mut self,
        _id: &channel::ChannelId,
        _receipt: &channel::ReceiptId,
    ) -> StoreResult<Read<channel::SavedUpdate>> {
        crate::error::later("channel receipt point read")
    }
    fn channel_saved(
        &mut self,
        _id: &channel::ChannelId,
        _after: u64,
    ) -> StoreResult<channel::ChannelRows<channel::SavedUpdate>> {
        crate::error::later("channel saved receipts")
    }
    fn channel_recent_rejections(
        &mut self,
        _id: &channel::ChannelId,
    ) -> StoreResult<channel::RecentRejections> {
        crate::error::later("recent channel input rejections")
    }
    fn channel_action(
        &mut self,
        _id: &channel::ChannelId,
        _action: &channel::ActionId,
    ) -> StoreResult<Read<channel::ResumeAction>> {
        crate::error::later("channel action")
    }
    fn channel_message_action(
        &mut self,
        _id: &channel::ChannelId,
        _message: &se_types::MessageId,
    ) -> StoreResult<Read<channel::ResumeAction>> {
        crate::error::later("channel message action")
    }
    fn channel_confirmed_actions(
        &mut self,
        _id: &channel::ChannelId,
    ) -> StoreResult<Vec<channel::ResumeAction>> {
        crate::error::later("confirmed channel actions")
    }
    fn channel_has_capacity(&mut self, _id: &channel::ChannelId) -> StoreResult<bool> {
        crate::error::later("channel pending capacity")
    }
    fn channel_due_delays(
        &mut self,
        _id: &channel::ChannelId,
        _at_us: i64,
    ) -> StoreResult<Vec<se_types::MessageId>> {
        crate::error::later("channel delayed status")
    }
    fn channel_pending_outputs(
        &mut self,
        _id: &channel::ChannelId,
        _at_us: i64,
    ) -> StoreResult<channel::ChannelRows<channel::Outbound>> {
        crate::error::later("pending channel output")
    }
    fn channel_replies(
        &mut self,
        _id: &channel::ChannelId,
        _original: &MessageId,
    ) -> StoreResult<channel::ChannelRows<channel::Outbound>> {
        crate::error::later("channel replies")
    }
    fn channel_outbox(
        &mut self,
        _id: &channel::ChannelId,
        _after: u64,
    ) -> StoreResult<channel::ChannelRows<channel::Outbound>> {
        crate::error::later("channel outbox")
    }
    fn channel_offset(&mut self, _id: &channel::ChannelId) -> StoreResult<Option<i64>> {
        crate::error::later("channel offset")
    }
    fn info(&self) -> StoreInfo;
    /// Encode an admitted, visible position for a public receipt/checked/history
    /// field. Binds store/incarnation, scope, principal and purpose; no arithmetic.
    fn position_cursor(
        &self,
        position: &StorePosition,
        purpose: PositionPurpose,
    ) -> StoreResult<se_types::Cursor>;
    /// Inverse of position_cursor for the same store, incarnation, scope,
    /// principal and purpose; any other cursor refuses rather than guessing.
    fn cursor_position(
        &self,
        cursor: &se_types::Cursor,
        purpose: PositionPurpose,
    ) -> StoreResult<StorePosition>;
    /// runtime.* facts are private: known excluded IDs return a typed refusal.
    /// Read a committed position from this exact store/incarnation and scope.
    fn event_position(&mut self, _position: &StorePosition) -> StoreResult<Read<StoredEvent>> {
        crate::error::later("event position read")
    }
    fn event(&mut self, id: EventId) -> StoreResult<Read<StoredEvent>>;
    /// Excludes runtime.* facts, including their native nonces.
    fn history(
        &mut self,
        query: HistoryQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>>;
    /// Excludes runtime.* facts before matching/snippet construction.
    fn search(&mut self, query: SearchQuery, budget: ReadBudget) -> StoreResult<SearchPage>;
    /// Non-mail mutable lists are labelled live keysets; Page describes this read only.
    fn projects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    /// Owner-only targeted lookup of removed registrations, retaining all matches
    /// so callers cannot silently resolve reused names or roots.
    fn removed_projects(
        &mut self,
        query: RemovedProjectQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>>;
    fn project(&mut self, id: ProjectId) -> StoreResult<Read<ProjectionRecord>>;
    fn principals(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn principal(&mut self, id: Actor) -> StoreResult<Read<ProjectionRecord>>;
    fn profile(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>>;
    /// Current permission projection. SelfOnly may read its own AgentCanCreate
    /// grant for authorization; this does not admit the event to ordinary reads.
    fn grant(&mut self, principal: Actor, key: GrantKey) -> StoreResult<Read<ProjectionRecord>>;
    fn session(&mut self, id: SessionId) -> StoreResult<Read<ProjectionRecord>>;
    fn sessions(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    /// One agent's most recent session in any state, ended and revoked
    /// included, with its original preparation; absent if it never had one.
    fn latest_session(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>>;
    fn message(&mut self, id: MessageId) -> StoreResult<Read<MessageRecord>>;
    /// Read the verified original source of this visible addressed message.
    /// Local mail returns None; missing remote provenance refuses. Later revoke
    /// cannot erase the identity under which an existing message committed.
    fn remote_message_attribution(
        &mut self,
        _id: MessageId,
    ) -> StoreResult<Option<se_types::remote::RemoteAttribution>> {
        Err(crate::error::fail(
            StoreErrorCode::Unreadable,
            "remote mail provenance reader is unavailable",
        ))
    }
    fn messages(
        &mut self,
        query: MessageQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>>;
    /// Exact matching count in this finite snapshot, independent of pagination.
    /// Uses the same actor/kind/unread and visibility predicates as messages.
    fn message_count(&mut self, query: MessageQuery) -> StoreResult<u64>;
    /// One immutable turn by its record ID, under this snapshot's project and visibility.
    fn turn(&mut self, id: RecordId) -> StoreResult<Read<StoredEvent>>;
    /// Resolve an item through this session's native conversation and agent.
    /// Codex resumes reuse the original immutable event across engine sessions.
    fn native_turn(
        &mut self,
        session: SessionId,
        provider: Provider,
        vendor: &str,
    ) -> StoreResult<Read<StoredEvent>>;
    fn turns(&mut self, agent: AgentId, budget: ReadBudget) -> StoreResult<Page<StoredEvent>>;
    /// Complete chat candidates for one captured native conversation and agent.
    fn conversation_turns(
        &mut self,
        _agent: AgentId,
        _provider: Provider,
        _native_ref: &str,
        _budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        crate::error::later("captured conversation turns")
    }
    /// The newest turns after `since`, oldest first; older turns the bound
    /// left out are counted exactly in the window's omitted-before.
    fn recent_turns(
        &mut self,
        agent: AgentId,
        since: Option<StorePosition>,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>>;
    /// Latest non-turn provider records and the independent latest compaction.
    /// Session=None reads this agent's continuity across its saved sessions.
    fn transcript_events(
        &mut self,
        agent: AgentId,
        session: Option<SessionId>,
        budget: ReadBudget,
    ) -> StoreResult<TranscriptRecords> {
        let _ = (agent, session, budget);
        crate::error::later("transcript metadata read")
    }
    fn capture_source(&mut self, source: RecordId) -> StoreResult<Read<ProjectionRecord>>;
    /// Latest failure/EOF verification after this source's current cursor.
    /// `kind` is None for either outcome, or CaptureFailed/CaptureVerified.
    /// Uses a reverse session-index seek rather than an oldest-first history page.
    fn capture_outcome(
        &mut self,
        source: RecordId,
        kind: Option<EventKind>,
    ) -> StoreResult<Read<StoredEvent>>;
    /// Launch/stop metadata for one agent under self, owner or creator control.
    /// A creator needs its current can-create grant and the target's immutable
    /// direct created_by, both read in this snapshot; other private reads are
    /// unchanged.
    fn control_target(&mut self, target: AgentId) -> StoreResult<Read<ControlTarget>>;
    fn process(&mut self, id: LifecycleId) -> StoreResult<Read<ProjectionRecord>>;
    /// Internal recorded custody for status/agent control, not a public process.list operation.
    fn processes(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn working_state(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>>;
    /// The agent's current cursor for one purpose and whether it was acknowledged.
    fn cursor(&mut self, agent: AgentId, purpose: String) -> StoreResult<Read<CursorHead>>;
    fn resume_head(&mut self, principal: Actor) -> StoreResult<Read<ResumeHead>>;
    fn pending_effects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    fn effect(&mut self, id: RecordId) -> StoreResult<Read<ProjectionRecord>>;
    fn integrations(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>>;
    /// Resolve the original key and semantic intent before native I/O or head checks.
    fn resolve_request(&mut self, _request: &RequestIdentity) -> StoreResult<Read<CommitReceipt>> {
        crate::error::later("keyed intent lookup")
    }
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
