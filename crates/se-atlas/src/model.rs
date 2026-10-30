use crate::errors::AtlasError;
use se_types::{AgentId, EventId, ProjectId};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RootId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheEpoch(pub [u8; 16]);
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
#[derive(Debug)]
pub struct RelativePath(pub(crate) String);
#[derive(Debug)]
pub struct AtlasCursor(pub(crate) String);
#[derive(Debug)]
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
#[derive(Debug)]
pub struct CodePointer {
    pub file: FileId,
    pub path: RelativePath,
    pub span: Option<Span>,
    pub content_hash: Option<ContentHash>,
}

#[derive(Debug)]
pub enum FileCoverage {
    Indexed,
    Partial { reasons: Vec<CoverageReason> },
    Deferred { reason: CoverageReason },
    Failed { error: AtlasError },
}
#[derive(Debug)]
pub struct Coverage {
    pub discovered_files: u64,
    pub indexed_files: u64,
    pub partial_files: u64,
    pub deferred_files: u64,
    pub failed_files: u64,
    pub discovery_complete: bool,
    pub reasons: Vec<CoverageReason>,
}

#[derive(Debug)]
pub enum IndexState {
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
        discovery_complete: bool,
    },
    Current,
    VerificationNeeded {
        reason: CoverageReason,
    },
    Suspended {
        reason: AtlasError,
    },
    Unreadable {
        error: AtlasError,
    },
    Draining,
    Closed,
}
#[derive(Debug)]
pub struct IndexSummary {
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: Option<CacheEpoch>,
    pub generation: Option<Generation>,
    pub state: IndexState,
    pub coverage: Coverage,
}
#[derive(Debug)]
pub struct Answer<T> {
    pub index: IndexSummary,
    pub data: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindMethod {
    ExactName,
    SplitIdentifier,
    MetadataFts,
    Text,
}
#[derive(Debug)]
pub struct CodeHit {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub name: String,
    pub kind: Option<SymbolKind>,
    pub method: FindMethod,
    pub accuracy: Option<Accuracy>,
}
#[derive(Debug)]
pub struct Reference {
    pub site: CodePointer,
    pub kind: ReferenceKind,
    pub spelling: String,
    pub enclosing: Option<SymbolId>,
    pub resolved_target: Option<SymbolId>,
    pub accuracy: Accuracy,
}
#[derive(Debug)]
pub struct ImpactHop {
    pub from: SymbolId,
    pub to: SymbolId,
    pub site: CodePointer,
    pub accuracy: Accuracy,
}
#[derive(Debug)]
pub struct Dependent {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub hops: Vec<ImpactHop>,
}
#[derive(Debug)]
pub struct Impact {
    pub dependents: Vec<Dependent>,
    pub tests: Vec<Dependent>,
    pub omitted_frontier: u64,
    pub frontier_count_complete: bool,
    pub next: Option<AtlasCursor>,
    pub complete: bool,
}

#[derive(Debug)]
pub enum AuthorHint {
    Captured { agent: AgentId, evidence: EventId },
    Mixed { evidence: Vec<EventId> },
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
#[derive(Debug)]
pub struct DependentCount {
    pub count: u64,
    pub at_generation: Generation,
    pub complete: bool,
    pub reason: Option<CoverageReason>,
}
#[derive(Debug)]
pub struct CodeChange {
    pub id: ChangeId,
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub kind: ChangeKind,
    pub previous_hash: Option<ContentHash>,
    pub author: AuthorHint,
    pub dependents: DependentCount,
}
#[derive(Debug)]
pub struct OutlineSymbol {
    pub id: SymbolId,
    pub parent: Option<SymbolId>,
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}
#[derive(Debug)]
pub struct Outline {
    pub file: CodePointer,
    pub language: Option<Language>,
    pub coverage: FileCoverage,
    pub symbols: Vec<OutlineSymbol>,
    pub complete: bool,
    pub next: Option<AtlasCursor>,
}

#[derive(Debug)]
pub struct CacheLocation {
    pub directory: PathBuf,
}
#[derive(Debug)]
pub struct RootRegistration {
    pub project: ProjectId,
    pub root: RootId,
    pub canonical_source_root: PathBuf,
    pub cache: CacheLocation,
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
#[derive(Debug)]
pub struct IgnorePolicy {
    pub global_patterns: Vec<String>,
    pub generated_prefixes: Vec<RelativePath>,
    pub digest: ContentHash,
}
#[derive(Debug)]
pub struct AtlasPolicy {
    pub ignore: IgnorePolicy,
    pub enabled: bool,
    pub max_files: u32,
    pub parse: ParseBudget,
    pub total_reserved_bytes: u32,
    pub change_retention_days: u16,
    pub max_change_rows: u32,
}
