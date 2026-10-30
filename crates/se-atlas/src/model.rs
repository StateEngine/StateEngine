use crate::errors::AtlasFailure;
use se_types::{AgentId, EventId, ProjectId};
pub use se_types::{AtlasRootId as RootId, IndexEpochId as CacheEpoch};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AtlasJobId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Generation(pub u64);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChangeId {
    pub generation: Generation,
    pub ordinal: u32,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SymbolId(pub [u8; 32]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentHash(pub [u8; 32]);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativePath(pub(crate) String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasCursor(pub(crate) String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryText(pub(crate) String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Language {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
    Rust,
    Python,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    Module,
    Namespace,
    Class,
    Interface,
    Trait,
    Struct,
    Enum,
    TypeAlias,
    Function,
    Method,
    Constant,
    Static,
    Variable,
    Parameter,
    Field,
    EnumVariant,
    Macro,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceKind {
    Call,
    Import,
    Export,
    TypeUse,
    ValueUse,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Accuracy {
    LexicalBinding,
    ExplicitImport,
    NameOnly,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageReason {
    UnsupportedLanguage,
    UnsupportedEncoding,
    Generated,
    SourceBytesLimit,
    ParseWorkLimit,
    FileCountLimit,
    ParseErrors,
    ReadFailure,
    ChangedDuringRead,
    UnresolvedImport,
    DynamicDispatch,
    StaleSnapshot,
    TimeLimit,
    ResultLimit,
    ByteLimit,
    WatchLoss,
    PartialWatch,
    ParserUnqualified,
    BaselineReset,
    BulkChange,
    RetentionGap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Position {
    pub line: u32,
    pub byte_column: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: Position,
    pub end: Position,
    pub start_byte: u64,
    pub end_byte: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotFreshness {
    Current,
    Stale,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodePointer {
    pub file: FileId,
    pub path: RelativePath,
    pub span: Option<Span>,
    pub content_hash: Option<ContentHash>,
    pub freshness: SnapshotFreshness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileCoverage {
    Indexed,
    Partial {
        reasons: Vec<CoverageReason>,
    },
    Deferred {
        reason: CoverageReason,
    },
    Failed {
        error: AtlasFailure,
    },
    Stale {
        reason: CoverageReason,
        last_good_generation: Generation,
        observed_hash: Option<ContentHash>,
        diagnostic: Option<AtlasFailure>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coverage {
    pub discovered_files: u64,
    pub indexed_files: u64,
    pub partial_files: u64,
    pub deferred_files: u64,
    pub failed_files: u64,
    pub discovery_complete: bool,
    pub stale_files: u64,
    pub resolved_references: u64,
    pub name_only_references: u64,
    pub watched_directories: u64,
    pub unwatched_directories: u64,
    pub watch_discovery_complete: bool,
    /// Process-lifetime counters; status reports scope/reset, never implies history.
    pub watch_stats_started: Option<se_types::UnixMicros>,
    pub watch_activation_attempts: u64,
    pub watch_limited_activations: u64,
    pub reasons: Vec<CoverageReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexState {
    NotBuilt,
    Disabled,
    Dormant,
    Absent,
    Opening,
    ColdIndexing {
        job: AtlasJobId,
        discovered_files: u64,
    },
    Updating {
        pending_files: u64,
        pending_change_batches: u32,
        discovery_complete: bool,
    },
    Current,
    VerificationNeeded {
        reason: CoverageReason,
    },
    Suspended {
        reason: AtlasFailure,
    },
    Unreadable {
        error: AtlasFailure,
    },
    Draining,
    Closed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexSummary {
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: Option<CacheEpoch>,
    pub generation: Option<Generation>,
    pub state: IndexState,
    pub coverage: Coverage,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer<T> {
    pub index: IndexSummary,
    pub snapshot_advanced: bool,
    pub epoch_retired: bool,
    pub data: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindMethod {
    ExactName,
    SplitIdentifier,
    MetadataFts,
    Text,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeHit {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub name: String,
    pub kind: Option<SymbolKind>,
    pub method: FindMethod,
    pub accuracy: Option<Accuracy>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference {
    pub site: CodePointer,
    pub kind: ReferenceKind,
    pub spelling: String,
    pub enclosing: Option<SymbolId>,
    pub resolved_target: Option<SymbolId>,
    pub accuracy: Accuracy,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpactHop {
    pub from: SymbolId,
    pub to: SymbolId,
    pub site: CodePointer,
    pub accuracy: Accuracy,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependent {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub hops: Vec<ImpactHop>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Impact {
    pub dependents: Vec<Dependent>,
    pub tests: Vec<Dependent>,
    pub omitted_frontier: u64,
    pub frontier_count_complete: bool,
    pub next: Option<AtlasCursor>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorHint {
    Captured {
        agent: AgentId,
        evidence: EventId,
    },
    Mixed {
        evidence: Vec<EventId>,
        omitted: Option<u64>,
    },
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    Added,
    Removed,
    SignatureChanged,
    BodyChanged,
    FileOnly,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependentCount {
    pub count: u64,
    pub at_generation: Generation,
    pub complete: bool,
    pub reason: Option<CoverageReason>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeEdit {
    pub id: ChangeId,
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub kind: ChangeKind,
    pub baseline_reset: bool,
    pub previous_hash: Option<ContentHash>,
    pub author: AuthorHint,
    pub dependents: DependentCount,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BulkReason {
    HeadChange,
    FilesystemBurst,
    IgnoreReconcile,
    WatchReconcile,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkChange {
    pub id: ChangeId,
    pub reason: BulkReason,
    pub files: u64,
    pub semantic_changes: Option<u64>,
    pub sample_paths: Vec<RelativePath>,
    pub complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodeChange {
    Edit(Box<CodeEdit>),
    Bulk(BulkChange),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceAtlasState {
    NotBuilt,
    Disabled,
    Absent,
    Updating,
    Ready,
    Unreadable,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutlineSymbol {
    pub id: SymbolId,
    pub parent: Option<SymbolId>,
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outline {
    pub file: CodePointer,
    pub language: Option<Language>,
    pub coverage: FileCoverage,
    pub symbols: Vec<OutlineSymbol>,
    pub complete: bool,
    pub next: Option<AtlasCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheLocation {
    pub directory: PathBuf,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePointer {
    pub schema: u32,
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: CacheEpoch,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitMetadataRegistration {
    pub physical_git_directory: PathBuf,
    pub physical_common_directory: PathBuf,
    pub git_directory_identity: [u8; 32],
    pub common_directory_identity: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRegistration {
    pub project: ProjectId,
    pub root: RootId,
    pub canonical_source_root: PathBuf,
    pub cache: CacheLocation,
    pub git_metadata: Option<GitMetadataRegistration>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryBudget {
    pub max_results: u16,
    pub max_bytes: u32,
    pub work: Duration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseBudget {
    pub max_source_bytes: u32,
    pub max_rows: u32,
    pub max_work: Duration,
    pub reserved_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IgnorePolicy {
    pub global_patterns: Vec<String>,
    pub generated_prefixes: Vec<RelativePath>,
    pub digest: ContentHash,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchBudget {
    /// Global host policy shared by roots, not a per-root allowance.
    pub max_directories: u32,
    pub max_mapping_bytes: u32,
    pub observed_os_limit: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasPolicy {
    pub ignore: IgnorePolicy,
    pub watch: WatchBudget,
    pub enabled: bool,
    pub max_files: u32,
    pub parse: ParseBudget,
    pub total_reserved_bytes: u32,
    pub change_retention_days: u16,
    pub max_change_rows: u32,
    pub max_cache_bytes: u64,
}
