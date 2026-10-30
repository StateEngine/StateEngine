use crate::HistoryFamily;
pub use se_types::StoreId;
use se_types::{
    AgentId, Cursor, EventId, Generation, HostEpoch, HumanId, IdempotencyKey, NativePath,
    ProjectId, Sequence, SessionId, UnixMicros, Window,
};
use std::{
    num::{NonZeroU16, NonZeroU32},
    path::PathBuf,
    time::Duration,
};

/// Logical internal object (effect/source/import/erasure/process record), never an OS PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordId {
    _bytes: [u8; 16],
}
/// UUIDv7 representation only; allocation supplies explicit time/entropy.
pub trait RecordIdentity: Sized {
    fn from_parts(unix_millis: u64, random: [u8; 10]) -> StoreResult<Self>;
    fn from_bytes(bytes: [u8; 16]) -> StoreResult<Self>;
    fn as_bytes(&self) -> &[u8; 16];
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revision {
    pub incarnation: u64,
    pub position: Sequence,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expected {
    Absent,
    Revision(Revision),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Actor {
    Human(HumanId),
    Agent(AgentId),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    Registry,
    Project(ProjectId),
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
    pub head: Option<Revision>,
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
    pub frozen_at: Revision,
    pub deadline_at: UnixMicros,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHandoverPhase {
    Prepared,
    ReadyToClaim,
    Claimed,
    Activated,
    Finished,
    Aborted,
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
    pub request_key: Option<IdempotencyKey>,
    pub state: CommitState,
    pub primary_event: EventId,
    pub writer: WriterMode,
    pub durability: CommitDurability,
    pub wakes: Vec<Wake>,
    pub first: Revision,
    pub last: Revision,
    pub events: Vec<EventId>,
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
    pub through: Revision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitState {
    Committed,
    Replayed,
    NaturalKeyReplay,
}
#[derive(Clone, Debug)]
pub struct FlushReport {
    pub through: Option<Revision>,
    pub pending_requests: u32,
    pub indeterminate: Vec<PendingOperation>,
}
#[derive(Clone, Debug)]
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
    _private: (),
}
#[derive(Clone, Debug)]
pub struct BackupGeneration {
    pub id: RecordId,
    pub through: Revision,
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
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    pub fingerprint: [u8; 32],
    pub from: u32,
    pub to: u32,
    pub source: StoreId,
    pub required_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct MigrationApproval {
    pub owner: HumanId,
    pub plan_fingerprint: [u8; 32],
    pub trigger: MigrationTrigger,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationTrigger {
    ExplicitOwnerCommand,
    ExplicitUpgrade,
}
#[derive(Clone, Debug)]
pub struct MigrationReport {
    pub schema_version: u32,
    pub incarnation: u64,
    pub backup: BackupGeneration,
}
#[derive(Clone, Debug)]
pub struct RecoveryGap {
    pub from: Option<Revision>,
    pub to: Option<Revision>,
    pub source_offset: Option<u64>,
    pub reason: String,
}
#[derive(Clone, Debug)]
pub struct SalvagePlan {
    pub source_store: Option<StoreId>,
    pub target_store: StoreId,
    pub source: PathBuf,
    pub candidate: PathBuf,
    pub source_sha256: [u8; 32],
    pub required_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct SalvageReport {
    pub candidate: PathBuf,
    pub source: Option<StoreId>,
    pub target: StoreId,
    pub recovered_events: u64,
    pub gaps: Vec<RecoveryGap>,
    pub complete: bool,
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
#[derive(Clone, Debug)]
pub struct ImportCheckpoint {
    pub import: RecordId,
    pub family: String,
    pub source_key: Vec<u8>,
    pub source_sha256: [u8; 32],
    pub byte_offset: u64,
    pub row_offset: u64,
    pub expected: Expected,
}
#[derive(Clone, Debug)]
pub struct ImportCounts {
    pub read: u64,
    pub imported: u64,
    pub duplicate: u64,
    pub unreadable: u64,
    pub dropped_by_policy: u64,
}
#[derive(Clone, Debug)]
pub struct ResumeHead {
    pub principal: Actor,
    pub turn: Option<Revision>,
    pub working_state: Option<Revision>,
    pub cursor: Option<Revision>,
    pub session: Option<Revision>,
    pub unread: u64,
    pub pending_effects: u64,
    pub through: Revision,
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
#[derive(Clone, Debug)]
pub enum StoreDetail {
    None,
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
    Maintenance {
        state: StoreState,
        operation: Option<RecordId>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreErrorCode {
    Absent,
    AlreadyExists,
    Unreadable,
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
    IdempotencyKeyReused,
    EventIdConflict,
    NaturalKeyConflict,
    RevisionConflict,
    InvalidTransition,
    ReferenceMissing,
    ScopeMismatch,
    CreatorControlRefused,
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
