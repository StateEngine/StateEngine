use crate::HistoryFamily;
pub use se_types::StoreId;
use se_types::{
    AgentId, Cursor, EventId, Generation, HostEpoch, HumanId, IdempotencyKey, NativePath,
    ProjectId, Sequence, SessionId, UnixMicros, Window,
};
use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    path::PathBuf,
    time::Duration,
};

/// Logical internal object (effect/source/import/erasure/process record), never an OS PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecordId {
    _bytes: [u8; 16],
}
/// UUIDv7 representation only; allocation supplies explicit time/entropy.
pub trait RecordIdentity: Sized {
    fn from_parts(unix_millis: u64, random: [u8; 10]) -> StoreResult<Self>;
    fn from_bytes(bytes: [u8; 16]) -> StoreResult<Self>;
    fn as_bytes(&self) -> &[u8; 16];
}
/// Per-entity counter: creation is one, committed changes increment by one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Revision {
    pub value: NonZeroU64,
}
/// Store-owned ordering token; never a wire revision or caller-selected sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorePosition {
    _store: StoreId,
    _incarnation: u64,
    _sequence: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PositionPurpose {
    Receipt,
    Checked,
    History,
    /// A resume/continuity position for exactly this target agent; it never
    /// decodes as a history cursor or for another target.
    Continuity(AgentId),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Expected {
    Absent,
    Revision(Revision),
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Actor {
    Human(HumanId),
    Agent(AgentId),
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Scope {
    Registry,
    Project(ProjectId),
}
/// Facts for the trusted native owner observer; these do not grant owner authority.
#[derive(Clone, Debug)]
pub struct OwnerGuardInventory {
    pub store: StoreInfo,
    pub owners: Vec<HumanId>,
    /// Any process row across this home, including exited, historical and released records.
    /// Read under the same protected snapshot as the unresolved native inventory.
    pub has_process_records: bool,
    /// Unreleased nonterminal heads, plus Exited heads whose exact session is
    /// still Prepared/Active and therefore owes startup capture/session cleanup.
    pub processes: Vec<OwnerGuardProcess>,
}
#[derive(Clone, Debug)]
pub struct OwnerGuardProcess {
    pub project: ProjectId,
    pub revision: Revision,
    pub state: crate::ProcessState,
    pub identity: crate::ProcessIdentityRecord,
}
/// Supplied by admitted core policy; this is not a deserializable authority credential.
#[derive(Clone, Debug)]
pub struct Admission {
    pub scope: Scope,
    pub actor: Actor,
    pub session: Option<SessionId>,
    pub generation: u64,
}
#[derive(Clone, Debug)]
pub enum Visibility {
    Owner,
    SelfOnly(AgentId),
    SharedProject(AgentId),
}
#[derive(Clone, Debug)]
pub struct ReadScope {
    pub admission: Admission,
    pub visibility: Visibility,
}
#[derive(Clone, Debug)]
pub struct StoreOptions {
    pub state_directory: PathBuf,
    pub busy_timeout: Duration,
}
#[derive(Clone, Debug)]
pub struct StoreInfo {
    pub id: StoreId,
    pub incarnation: u64,
    pub schema_version: u32,
    pub head: Option<StorePosition>,
    pub state: StoreState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreState {
    Ready,
    Migrating,
    Recovering,
    Erasing,
}
#[derive(Clone, Debug)]
pub struct LeaseIdentity {
    pub store: Option<StoreId>,
    pub generation: u64,
    pub mode: LeaseMode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseMode {
    Host,
    DirectClient,
}
/// One transfer identity and immutable manifest binding; phase advances by CAS.
/// Nonce is private native peer-binding material, so the record is not Debug.
#[derive(Clone)]
pub struct RuntimeHandoverRecord {
    pub transfer: RecordId,
    pub native_nonce: [u8; 16],
    pub source_epoch: HostEpoch,
    pub successor_epoch: HostEpoch,
    pub source_generation: Generation,
    pub successor_generation: Generation,
    pub phase: RuntimeHandoverPhase,
    pub manifest_sha256: [u8; 32],
    pub frozen_at: StorePosition,
    pub deadline_at: UnixMicros,
    /// Present only for Finished; verified before ordinary consumers start.
    pub completion: Option<Box<RuntimeHandoverCompletion>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHandoverPhase {
    Prepared,
    Claimed,
    Finished,
    Aborted,
    /// Terminal resolution recorded inside the fresh FULL runtime.owner fact.
    Recovered,
}
/// Finished binds native activation and outside source-resource closure in one FULL fact.
#[derive(Clone)]
pub struct RuntimeHandoverCompletion {
    pub activated_custody_sha256: [u8; 32],
    pub capture_at: StorePosition,
    pub queue_cut_sha256: [u8; 32],
    pub source_closed_sha256: [u8; 32],
}
/// Binds checked cold ownership to the original transfer without rewriting peers.
/// The enclosing event header is the new owner/completion EventId.
#[derive(Clone)]
pub struct RuntimeRecoveredTransfer {
    pub transfer: RecordId,
    pub handover_event: EventId,
    pub activated_custody_sha256: [u8; 32],
    pub capture_at: StorePosition,
    pub queue_cut_sha256: [u8; 32],
}
/// Non-secret singleton view; private transfer material stays on the host port.
#[derive(Clone, Debug)]
pub struct RuntimeOwnerHead {
    pub epoch: HostEpoch,
    pub generation: Generation,
    pub event: EventId,
    pub revision: Revision,
    pub handover: Option<RuntimeHandoverHead>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeHandoverHead {
    pub transfer: RecordId,
    pub phase: RuntimeHandoverPhase,
}
#[derive(Clone, Debug)]
pub struct WriterOptions {
    pub maximum_requests: NonZeroU16,
    pub queue_requests: NonZeroU16,
    pub resident_bytes: NonZeroU32,
    pub group_bytes: NonZeroU32,
}
#[derive(Clone, Debug)]
pub struct ReadBudget {
    pub page: se_types::PageRequest,
    pub deadline: Duration,
}

/// Core computes this from the closed admitted operation input, before allocating IDs.
/// Includes caller-explicit expectations; excludes default head reads and allocated outputs.
/// It is never accepted from JSON/MCP or a caller-selected environment value.
#[derive(Clone, Debug)]
pub struct IntentDigest {
    pub operation: &'static str,
    pub codec_version: u16,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct RequestIdentity {
    pub key: IdempotencyKey,
    pub intent: IntentDigest,
}
#[derive(Clone, Debug)]
pub struct CommitReceipt {
    /// Current host submission only; never persisted or reconstructed on receipt lookup.
    /// Direct writes and retained receipt reads leave this absent.
    pub write_timings: Option<crate::WriteTimings>,
    /// A known commit succeeded but its checkpoint/maintenance still needs retry.
    pub maintenance_pending: bool,
    pub request_key: Option<IdempotencyKey>,
    pub state: CommitState,
    pub primary_event: EventId,
    pub writer: WriterMode,
    pub durability: CommitDurability,
    pub wakes: Vec<Wake>,
    pub first: StorePosition,
    pub last: StorePosition,
    pub events: Vec<EventId>,
}
/// Trusted maintenance input, not a public operation or cross-scope admission.
/// Owner is one registry runtime.owner; session is the witnessed project binding.
pub struct FirstBinding {
    pub owner: crate::AtomicBatch,
    pub session: crate::AtomicBatch,
}
/// Two scoped operation receipts from the same successful outer FULL commit.
pub struct FirstBindingReceipt {
    pub owner: CommitReceipt,
    pub session: CommitReceipt,
}
/// Constructed only by the canonical store committer or retained-event decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterMode {
    _kind: WriterKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterKind {
    Host { generation: u64 },
    Direct,
}
pub trait WriterModeValue {
    fn kind(&self) -> WriterKind;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDurability {
    Normal,
    Full,
}
#[derive(Clone, Debug)]
pub struct Wake {
    pub project: ProjectId,
    pub principal: Actor,
    pub through: StorePosition,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitState {
    Committed,
    Replayed,
    NaturalKeyReplay,
}
#[derive(Clone, Debug)]
pub struct FlushReport {
    pub maintenance_pending: bool,
    pub through: Option<StorePosition>,
    pub pending_requests: u32,
    pub indeterminate: Vec<PendingOperation>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingOperation {
    CallerKey(IdempotencyKey),
    NaturalEvents(Vec<EventId>),
}
#[derive(Clone, Debug)]
pub struct CheckpointReport {
    pub wal_frames: u64,
    pub checkpointed_frames: u64,
    pub busy: bool,
}
/// Store-owned shared backup/WAL coordination; no public constructor or mutator.
/// Private implementation retains store/incarnation/generation and pin/cancel state.
#[derive(Clone)]
pub struct BackupContext {
    pub(crate) state: std::sync::Arc<crate::backup_context::State>,
}
#[derive(Clone, Debug)]
pub struct BackupGeneration {
    pub id: RecordId,
    pub through: StorePosition,
    pub schema_version: u32,
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub path: PathBuf,
}
#[derive(Clone, Debug)]
pub struct BackupReport {
    pub published: BackupGeneration,
    pub retained: Vec<BackupGeneration>,
    pub removed: Vec<RecordId>,
}
/// Immutable outcome read from the published recovery fact, not current file state.
#[derive(Clone)]
pub struct RestoreReceipt {
    /// Exact complete original se.restore/v1 UTF-8 JSON (max 1 MiB); emit verbatim.
    /// Includes the original plan, witnesses, state and completeness; never reconstructed.
    pub original_receipt: String,
    pub request_key: IdempotencyKey,
    pub event: EventId,
    pub backup: RecordId,
    pub source: Option<StoreId>,
    pub source_incarnation: Option<u64>,
    pub target: StoreId,
    pub target_incarnation: u64,
    pub restored_through: StorePosition,
    pub loss: RestoreLoss,
    pub writer: WriterMode,
}
pub struct RestoreOutcome<H> {
    pub host: H,
    pub receipt: RestoreReceipt,
}
/// Post-backup range lost on explicit restore; None means its upper bound is unknown.
#[derive(Clone, Debug)]
pub struct RestoreLoss {
    pub after: StorePosition,
    pub prior_head: Option<StorePosition>,
}
#[derive(Clone, Debug)]
pub enum EraseField {
    Body,
    SourceDigest,
}
#[derive(Clone, Debug)]
pub struct EraseTarget {
    pub event: EventId,
    pub expected: Revision,
}
#[derive(Clone, Debug)]
pub struct ResidualCopy {
    pub custodian: String,
    pub location: NativePath,
    pub reason: String,
}
#[derive(Clone, Debug)]
pub struct ErasurePlan {
    pub id: RecordId,
    pub targets: Vec<EraseTarget>,
    pub owned_generations: Vec<RecordId>,
    pub residuals: Vec<ResidualCopy>,
    pub required_bytes: u64,
}
/// Host supplies actual buffer/consumer readback; mere callback completion is not a witness.
#[derive(Clone, Debug)]
pub struct ErasureApproval {
    pub erasure: RecordId,
    pub owner: HumanId,
    pub expected_incarnation: u64,
    pub buffer_witnesses: Vec<EventId>,
    pub accept_named_residuals: bool,
}
#[derive(Clone, Debug)]
pub struct ErasureReport {
    pub erasure: RecordId,
    pub completed_event: Option<EventId>,
    pub cleanup_complete: bool,
    pub incarnation: u64,
    pub erased_fields: Vec<EraseTarget>,
    pub residuals: Vec<ResidualCopy>,
}
/// User history only; no fleet/runtime/configuration repair protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFamily {
    Projects,
    Owners,
    Agents,
    Profiles,
    Messages,
    Decisions,
    WorkingState,
    Conversations,
    Turns,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ImportCheckpoint {
    pub import: RecordId,
    pub family: ImportFamily,
    pub source_key: Vec<u8>,
    pub source_sha256: [u8; 32],
    pub byte_offset: u64,
    pub row_offset: u64,
    pub expected: Expected,
}
pub use crate::import::counts::ImportCounts;
#[derive(Clone, Debug)]
pub struct ResumeHead {
    pub principal: Actor,
    pub turn: Option<StorePosition>,
    pub working_state: Option<StorePosition>,
    pub cursor: Option<StorePosition>,
    pub session: Option<StorePosition>,
    pub unread: u64,
    pub pending_effects: u64,
    pub through: StorePosition,
}
#[derive(Clone, Debug)]
pub struct CursorRecord {
    pub id: RecordId,
    pub agent: AgentId,
    pub purpose: String,
    pub value: Cursor,
    pub window: Window,
    pub expected: Expected,
}
#[derive(Clone, Debug)]
pub struct StoreError {
    pub code: StoreErrorCode,
    pub cause: String,
    pub detail: StoreDetail,
    pub remedy: se_types::Remedy,
    pub retry: se_types::Retry,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreIoStage {
    Open,
    PragmaReadback,
    BeginSnapshot,
    HeaderReadback,
    ReadSnapshot,
}
#[derive(Clone, Debug)]
pub enum StoreDetail {
    None,
    PrincipalNameConflict {
        project: ProjectId,
        name: String,
        existing: Actor,
    },
    Sqlite {
        extended_code: i32,
        native_os_code: Option<i32>,
    },
    Io {
        /// Path relative to the state directory; never an absolute home or request path.
        path: String,
        /// Exact SQLite filename for trusted diagnostics, including native path prefixes.
        opened_path: String,
        stage: StoreIoStage,
        sqlite_extended_code: Option<i32>,
        /// Captured from the failing native call, never ambient last-error state.
        native_os_code: Option<i32>,
    },
    Conflict {
        expected: Expected,
        observed: Option<Revision>,
    },
    Version {
        application_id: u32,
        found: u32,
        minimum: u32,
        maximum: u32,
    },
    Request {
        scope: Scope,
        actor: Actor,
        key: IdempotencyKey,
        /// Present for a conflicting retained caller key; never a minted ID.
        original_event: Option<EventId>,
    },
    Entity {
        family: HistoryFamily,
        event: Option<EventId>,
        record: Option<RecordId>,
    },
    Source {
        path: NativePath,
        offset: Option<u64>,
        length: Option<u64>,
        sqlite_extended_code: Option<i32>,
    },
    Budget {
        allowed: u64,
        required: Option<u64>,
    },
    Space {
        required: Option<u64>,
        available: Option<u64>,
    },
    Maintenance {
        state: StoreState,
        operation: Option<RecordId>,
    },
    /// The removed project and when its tombstone was recorded.
    ProjectRemoved {
        project: ProjectId,
        at: UnixMicros,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreErrorCode {
    Absent,
    AlreadyExists,
    Unreadable,
    Corrupt,
    ApplicationMismatch,
    TooNew,
    VersionUnsupported,
    MigrationRequired,
    NotReady,
    GenerationChanged,
    LocationUnsafe,
    PragmaRefused,
    Busy,
    Backpressure,
    WriterClosed,
    CommitOutcomeUnknown,
    DiskFull,
    IdempotencyKeyReused,
    EventIdConflict,
    NaturalKeyConflict,
    RevisionConflict,
    InvalidTransition,
    ReferenceMissing,
    ScopeMismatch,
    CreatorControlRefused,
    /// The project was tombstoned; its history stays readable, writes refuse.
    ProjectRemoved,
    EventInvalid,
    BodyTooLarge,
    ProjectionInconsistent,
    CursorInvalid,
    CursorStale,
    ReadBudgetTooSmall,
    ReadIncomplete,
    SourceChanged,
    MigrationFailed,
    BackupFailed,
    RecoveryIncomplete,
    ContentErased,
    ErasureIncomplete,
    ErasureExternalCopies,
    ErasurePhysicalGuaranteeUnavailable,
}
pub type StoreResult<T> = std::result::Result<T, Box<StoreError>>;

impl RecordId {
    pub(crate) fn new_internal(bytes: [u8; 16]) -> Self {
        Self { _bytes: bytes }
    }
    pub(crate) fn bytes_internal(&self) -> &[u8; 16] {
        &self._bytes
    }
}
impl StorePosition {
    pub(crate) fn new_internal(
        store: StoreId,
        incarnation: u64,
        sequence: u64,
    ) -> StoreResult<Self> {
        Ok(Self {
            _store: store,
            _incarnation: incarnation,
            _sequence: Sequence::new(sequence).map_err(crate::error::invalid)?,
        })
    }
    pub(crate) fn sequence(&self) -> u64 {
        self._sequence.get()
    }
    pub(crate) fn storage_parts(&self) -> (&StoreId, u64, u64) {
        (&self._store, self._incarnation, self.sequence())
    }
    pub(crate) fn belongs(&self, info: &StoreInfo) -> bool {
        self._store == info.id && self._incarnation == info.incarnation
    }
}
impl WriterMode {
    pub(crate) fn from_lease(lease: &LeaseIdentity) -> Self {
        Self {
            _kind: match lease.mode {
                LeaseMode::Host => WriterKind::Host {
                    generation: lease.generation,
                },
                LeaseMode::DirectClient => WriterKind::Direct,
            },
        }
    }
}
impl WriterModeValue for WriterMode {
    fn kind(&self) -> WriterKind {
        self._kind
    }
}
