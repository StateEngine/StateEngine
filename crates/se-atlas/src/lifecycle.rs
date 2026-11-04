use crate::{errors::AtlasResult, model::*, queries::AtlasQueries};
use se_types::{AgentId, EventId};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileReason {
    ConfigEnabled,
    FirstSession,
    HostRestart,
    WatchOverflow,
    WatchFailure,
    IgnoreRulesChanged,
    GitHeadChanged,
    GitActivity,
    DirectoryChanged,
    ExtractorChanged,
    ConfigurationChanged,
}
#[derive(Debug)]
pub enum SourceHint {
    FileChanged(RelativePath),
    FileRemoved(RelativePath),
    Rename {
        from: RelativePath,
        to: RelativePath,
    },
    Reconcile(ReconcileReason),
}
#[derive(Debug)]
pub struct EditEvidence {
    pub agent: AgentId,
    pub event: EventId,
    pub path: RelativePath,
    pub before: Option<ContentHash>,
    pub after: Option<ContentHash>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleReceipt {
    Queued,
    Coalesced,
    ReconciliationRequired,
    Disabled,
    Closing,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkPhase {
    Discover,
    Read,
    Parse,
    Resolve,
    Diff,
    Commit,
    Prune,
    Checkpoint,
}
#[derive(Debug)]
pub struct WorkReport {
    pub root: RootId,
    pub phase: WorkPhase,
    pub completed_files: u32,
    pub remaining_known: u32,
    pub generation: Option<Generation>,
    pub state: IndexState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextWork {
    Park,
    Ready,
    AfterEventDebounce(Duration),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    Disabled,
    HostDrain,
    ProjectRemoved,
    PrivacyErasure,
}
#[derive(Debug)]
pub enum CloseResult {
    Closed,
    Pending { in_flight: u32 },
    Refused { error: crate::errors::AtlasFailure },
}
#[derive(Debug)]
pub struct CacheRemoval {
    pub root: RootId,
    pub database_absent: bool,
    pub wal_absent: bool,
    pub shm_absent: bool,
    pub remaining_paths: Vec<std::path::PathBuf>,
}

/// Host-internal lifecycle, never added to OPS as another user operation.
/// A single host-owned low-priority worker owns this mutable value.
pub trait AtlasController {
    type Reader: AtlasQueries;
    fn register(
        &mut self,
        root: RootRegistration,
        policy: AtlasPolicy,
    ) -> AtlasResult<IndexSummary>;
    fn activate(&mut self, root: RootId, reason: ReconcileReason) -> AtlasResult<ScheduleReceipt>;
    fn enqueue(&mut self, root: RootId, hint: SourceHint) -> AtlasResult<ScheduleReceipt>;
    fn captured_edit(
        &mut self,
        root: RootId,
        evidence: EditEvidence,
    ) -> AtlasResult<ScheduleReceipt>;
    fn work_quantum(&mut self, allowance: Duration) -> AtlasResult<Option<WorkReport>>;
    fn next_work(&self) -> NextWork;
    fn reader(&self, root: RootId) -> AtlasResult<Self::Reader>;
    fn close(
        &mut self,
        root: RootId,
        reason: CloseReason,
        deadline: Duration,
    ) -> AtlasResult<CloseResult>;
    fn remove_cache(&mut self, root: RootId) -> AtlasResult<CacheRemoval>;
    fn forget_evidence(&mut self, root: RootId, events: &[EventId]) -> AtlasResult<CacheRemoval>;
    fn take_child_request(&mut self) -> AtlasResult<Option<WorkerRequest>>;
    fn child_event(&mut self, event: WorkerEvent) -> AtlasResult<ScheduleReceipt>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerPurpose {
    ColdIndex,
}
#[derive(Debug)]
pub struct WorkerReservation {
    /// B4 is measured outside the separate cold window.
    pub host_steady_ceiling_bytes: u64,
    /// Hard cold-child peak, separately observed during the window.
    pub child_peak_bytes: u64,
    pub wall_deadline: Duration,
}
#[derive(Debug)]
pub struct WorkerRequest {
    pub job: AtlasJobId,
    pub root: RootRegistration,
    pub expected_epoch: Option<CacheEpoch>,
    pub purpose: WorkerPurpose,
    pub paths: Vec<RelativePath>,
    pub reservation: WorkerReservation,
    pub policy: AtlasPolicy,
}
#[derive(Debug)]
pub enum WorkerEvent {
    Started {
        job: AtlasJobId,
    },
    Progress {
        job: AtlasJobId,
        discovered: u64,
        completed: u64,
    },
    Exited {
        job: AtlasJobId,
        outcome: WorkerExit,
    },
}
#[derive(Debug)]
pub enum WorkerExit {
    Completed {
        staged_cache: CacheLocation,
        candidate_epoch: CacheEpoch,
    },
    Failed {
        error: crate::errors::AtlasFailure,
    },
    Cancelled,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseMode {
    Sensitive,
    InsensitivePreserving,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RevisionTrust {
    Unverified,
    QualifiedChangeSequence,
    QualifiedCtime,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FileIdentity {
    pub volume: [u8; 16],
    pub file: [u8; 16],
    pub size: u64,
    pub mtime_unix_nanos: i128,
    pub ctime_unix_nanos: Option<i128>,
    pub change_sequence: Option<u64>,
    /// Reset/replaced journal domains invalidate saved sequence comparisons.
    pub sequence_domain: Option<[u8; 16]>,
    /// Supplied only by a qualified native adapter, never request metadata.
    pub revision_trust: RevisionTrust,
}
#[derive(Debug)]
pub struct SourceSnapshot {
    pub path: RelativePath,
    pub identity: FileIdentity,
    pub content_hash: ContentHash,
    pub bytes: Vec<u8>,
}
#[derive(Debug)]
pub enum SourceRead {
    Bytes(SourceSnapshot),
    Deferred {
        identity: FileIdentity,
        reason: CoverageReason,
    },
    Removed,
}
#[derive(Debug)]
pub struct SourceChunk {
    pub path: RelativePath,
    pub identity: FileIdentity,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub end_of_file: bool,
    /// Hash of this verified range only; never a full-file revision by inference.
    pub range_hash: ContentHash,
    /// Present only after full-file verification, never inferred from stat identity.
    pub content_revision: Option<ContentHash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceVerification {
    Unchanged,
    Changed,
    Removed,
}

/// Uses the registered physical root, no-follow opens and native identity checks.
/// OS-specific unsafe code remains behind the host/se-proc adapter.
/// verify rehashes the entire admitted file before semantic commit. Reconcile
/// may skip unchanged files only with a qualified native revision proof, never
/// plain identity/size/mtime. read_chunk rereads/verifies the requested bounded range and
/// never promises a resumable snapshot across calls.
pub trait AtlasSource {
    fn case_mode(&self) -> CaseMode;
    fn read(&self, path: &RelativePath, budget: ParseBudget) -> AtlasResult<SourceRead>;
    fn verify(&self, snapshot: &SourceSnapshot) -> AtlasResult<SourceVerification>;
    fn read_chunk(
        &self,
        path: &RelativePath,
        offset: u64,
        max_bytes: u32,
    ) -> AtlasResult<Option<SourceChunk>>;
}

#[derive(Debug)]
pub struct SymbolRecord {
    pub id: SymbolId,
    pub parent: Option<SymbolId>,
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
    pub exported: bool,
    /// None means absent syntax; Some(hash(empty)) means an actual empty body.
    pub signature_hash: Option<ContentHash>,
    pub body_hash: Option<ContentHash>,
    pub doc_line: String,
    pub lexical_scope: u32,
}
#[derive(Debug)]
pub struct ImportRecord {
    pub spelling: String,
    pub local_name: Option<String>,
    pub imported_name: Option<String>,
    pub target_file: Option<FileId>,
    pub target_symbol: Option<SymbolId>,
    pub span: Span,
    pub kind: ImportKind,
    pub lexical_scope: u32,
    pub reexport: bool,
    pub wildcard: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportKind {
    Esm,
    CommonJs,
    Rust,
    Python,
}
#[derive(Debug)]
pub struct LexicalScope {
    pub parent: Option<u32>,
    pub span: Span,
}
#[derive(Debug)]
pub enum ReferenceQualifier {
    Unqualified,
    Namespace(Vec<String>),
    Dynamic,
}
#[derive(Debug)]
pub struct ParsedReference {
    pub site: Reference,
    pub lexical_scope: u32,
    pub qualifier: ReferenceQualifier,
}
#[derive(Debug)]
pub struct ParsedFile {
    pub file: FileId,
    pub language: Language,
    pub content_hash: ContentHash,
    pub coverage: FileCoverage,
    pub symbols: Vec<SymbolRecord>,
    pub imports: Vec<ImportRecord>,
    pub references: Vec<ParsedReference>,
    pub scopes: Vec<LexicalScope>,
}

pub trait AtlasParser {
    fn parse(
        &mut self,
        snapshot: &SourceSnapshot,
        language: Language,
        budget: ParseBudget,
    ) -> AtlasResult<ParsedFile>;
    fn release_scratch(&mut self);
}
