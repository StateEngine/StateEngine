//! Shared Atlas query/result values. No indexer, native handle, SQL or runtime dependency.
//! `se-atlas` reexports these; core consumes them without depending on se-atlas.
//! Opaque text is constructed through the shared pure validation contract below.
use crate::{AgentId, ErrorBody, EventId, ProjectId};
pub use crate::{AtlasRootId as RootId, IndexEpochId as CacheEpoch};
use std::time::Duration;
mod resources;
pub use resources::{GrammarPages, MemoryBudget};

/// Wire form of this module's byte-array IDs: a lowercase hex string on the
/// wire, never a JSON number array. Persisted caches keep reading because
/// the decoder also accepts the legacy array form.
mod id_encoding {
    use std::fmt;
    use std::marker::PhantomData;

    use serde::Deserializer;
    use serde::de::{Error, SeqAccess, Visitor};

    struct Bytes<const N: usize>(PhantomData<[u8; N]>);

    impl<'de, const N: usize> Visitor<'de> for Bytes<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "a hex string of {N} bytes or a legacy byte array"
            )
        }

        fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
            crate::decode_hex(value)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| E::invalid_value(serde::de::Unexpected::Str(value), &self))
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut bytes = [0; N];
            for slot in &mut bytes {
                *slot = seq
                    .next_element::<u8>()?
                    .ok_or_else(|| A::Error::invalid_length(N, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::invalid_length(N, &self));
            }
            Ok(bytes)
        }
    }

    pub(super) fn decode<'de, const N: usize, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        deserializer.deserialize_any(Bytes::<N>(PhantomData))
    }
}

macro_rules! wire_id {
    ($name:ident, $pattern:literal) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&crate::hex_lower(&self.0))
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                id_encoding::decode(deserializer).map(Self)
            }
        }
        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({"type":"string","pattern":$pattern})
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AtlasJobId(pub [u8; 16]);
wire_id!(AtlasJobId, "^[0-9a-f]{32}$");
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct Generation(pub u64);
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct ChangeId {
    pub generation: Generation,
    pub ordinal: u32,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileId(pub [u8; 16]);
wire_id!(FileId, "^[0-9a-f]{32}$");
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SymbolId(pub [u8; 32]);
wire_id!(SymbolId, "^[0-9a-f]{64}$");
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentHash(pub [u8; 32]);
wire_id!(ContentHash, "^[0-9a-f]{64}$");
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct RelativePath(pub(crate) String);
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct AtlasCursor(pub(crate) String);
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct QueryText(pub(crate) String);

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum Language {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
    Rust,
    Python,
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum ReferenceKind {
    Call,
    Import,
    Export,
    TypeUse,
    ValueUse,
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum Accuracy {
    LexicalBinding,
    ExplicitImport,
    NameOnly,
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum CoverageReason {
    UnsupportedLanguage,
    UnsupportedEncoding,
    Generated,
    SourceBytesLimit,
    ParseWorkLimit,
    ParseMemoryLimit,
    SchedulingStall,
    FileCountLimit,
    ParseErrors,
    ReadFailure,
    ChangedDuringRead,
    UnresolvedImport,
    DynamicDispatch,
    StaleSnapshot,
    RecordFeedLag,
    RecordBodyLimit,
    TimeLimit,
    ResultLimit,
    ByteLimit,
    WatchLoss,
    PartialWatch,
    ParserUnqualified,
    HistoryUnavailable,
    BaselineReset,
    BulkChange,
    RetentionGap,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Position {
    pub line: u32,
    pub byte_column: u32,
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Span {
    pub start: Position,
    pub end: Position,
    pub start_byte: u64,
    pub end_byte: u64,
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum SnapshotFreshness {
    Current,
    Stale,
    Unknown,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct CodePointer {
    pub file: FileId,
    pub path: RelativePath,
    pub span: Option<Span>,
    pub content_hash: Option<ContentHash>,
    pub freshness: SnapshotFreshness,
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum FileCoverage {
    Indexed,
    Partial {
        reasons: Vec<CoverageReason>,
    },
    Deferred {
        reason: CoverageReason,
    },
    Failed {
        error: ErrorBody,
    },
    Stale {
        reason: CoverageReason,
        last_good_generation: Generation,
        observed_hash: Option<ContentHash>,
        diagnostic: Option<ErrorBody>,
    },
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
    pub watch_stats_started: Option<crate::UnixMicros>,
    pub watch_activation_attempts: u64,
    pub watch_limited_activations: u64,
    pub reasons: Vec<CoverageReason>,
    /// Optional Git enrichment failed; source coverage remains independently usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_unavailable: Option<ErrorBody>,
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
    /// A published, readable index retains a concrete per-file failure.
    Partial {
        error: ErrorBody,
    },
    VerificationNeeded {
        reason: CoverageReason,
    },
    Suspended {
        reason: ErrorBody,
    },
    Unreadable {
        error: ErrorBody,
    },
    Draining,
    Closed,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct IndexSummary {
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: Option<CacheEpoch>,
    pub generation: Option<Generation>,
    pub state: IndexState,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryBudget>,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Answer<T> {
    pub index: IndexSummary,
    pub snapshot_advanced: bool,
    pub epoch_retired: bool,
    pub data: T,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum FindMethod {
    ExactName,
    SplitIdentifier,
    MetadataFts,
    Text,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct CodeHit {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub name: String,
    pub kind: Option<SymbolKind>,
    pub method: FindMethod,
    pub accuracy: Option<Accuracy>,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Reference {
    pub site: CodePointer,
    pub kind: ReferenceKind,
    pub spelling: String,
    pub enclosing: Option<SymbolId>,
    pub resolved_target: Option<SymbolId>,
    pub accuracy: Accuracy,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ImpactHop {
    pub from: SymbolId,
    pub to: SymbolId,
    pub site: CodePointer,
    pub accuracy: Accuracy,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Dependent {
    pub pointer: CodePointer,
    pub symbol: Option<SymbolId>,
    pub hops: Vec<ImpactHop>,
    #[serde(default)]
    pub file_hops: Vec<FileImpactHop>,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Impact {
    pub dependents: Vec<Dependent>,
    pub tests: Vec<Dependent>,
    pub records: Vec<RecordHit>,
    pub omitted_frontier: u64,
    pub frontier_count_complete: bool,
    pub next: Option<AtlasCursor>,
    pub complete: bool,
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum ChangeKind {
    Added,
    Removed,
    SignatureChanged,
    BodyChanged,
    FileOnly,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct DependentCount {
    pub count: u64,
    pub at_generation: Generation,
    pub complete: bool,
    pub reason: Option<CoverageReason>,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum BulkReason {
    HeadChange,
    FilesystemBurst,
    IgnoreReconcile,
    WatchReconcile,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct BulkChange {
    pub id: ChangeId,
    pub reason: BulkReason,
    pub files: u64,
    pub semantic_changes: Option<u64>,
    pub sample_paths: Vec<RelativePath>,
    pub complete: bool,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum CodeChange {
    Edit(Box<CodeEdit>),
    Bulk(BulkChange),
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum SurfaceAtlasState {
    NotBuilt,
    Disabled,
    Absent,
    Updating,
    Ready,
    Unreadable,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct OutlineSymbol {
    pub id: SymbolId,
    pub parent: Option<SymbolId>,
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Outline {
    pub file: CodePointer,
    pub language: Option<Language>,
    pub coverage: FileCoverage,
    pub symbols: Vec<OutlineSymbol>,
    pub records: Vec<RecordHit>,
    pub complete: bool,
    pub next: Option<AtlasCursor>,
}

mod query;
pub use query::*;
mod records;
pub use records::*;
mod search;
pub use search::*;
mod validation;
pub use validation::Validate;
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResumeRequest {
    pub viewer: AgentId,
    pub saved_cursor: Option<AtlasCursor>,
    pub cursor_revision: u64,
    pub recently_edited_symbols: Vec<SymbolId>,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum ResumeCodeState {
    Available,
    Zero,
    NeverIndexed,
    Disabled,
    Unreadable,
    BaselineGap,
    Updating,
    BudgetExceeded,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeOfferId(pub [u8; 16]);
wire_id!(ResumeOfferId, "^[0-9a-f]{32}$");
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum ResumeChange {
    File {
        pointer: CodePointer,
        kinds: Vec<ChangeKind>,
        changes: u64,
        author: AuthorHint,
        dependents: DependentCount,
        late_attribution: bool,
        baseline_reset: bool,
    },
    Bulk(BulkChange),
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ResumeAdvance {
    pub offer: ResumeOfferId,
    pub expected_cursor: Option<AtlasCursor>,
    pub expected_revision: u64,
    pub next_cursor: AtlasCursor,
    pub fence: Generation,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub enum ResumeCursorCommit {
    Applied { revision: u64 },
    AlreadyApplied { revision: u64 },
    Stale { actual_revision: u64 },
}
/// Model-visible status; private delivery/CAS controls are never serialized here.
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ResumeCodeStatus {
    pub state: ResumeCodeState,
    pub complete: bool,
    /// None means the omitted count is unknown, never zero.
    pub omitted: Option<u64>,
    pub unattributed_omitted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted_since: Option<AtlasCursor>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ResumeCode {
    pub index: IndexSummary,
    pub state: ResumeCodeState,
    /// The surface's $.code_changes array, never a pre-rendered string.
    pub items: Vec<ResumeChange>,
    pub omitted: Option<u64>,
    pub unattributed_omitted: Option<u64>,
    pub complete: bool,
    /// Lossless explicit changes retrieval starts here, independently of digest delivery.
    pub omitted_since: Option<AtlasCursor>,
    pub advance: Option<ResumeAdvance>,
    pub diagnostic: Option<ErrorBody>,
}

/// Shared pure constructors/decoders. Validate supplies the common ingress
/// implementation; scoped cursor payload checks remain with the query reader.
pub trait AtlasValidation {
    fn relative_path(&self, value: String) -> crate::Result<RelativePath>;
    fn query_text(&self, value: String) -> crate::Result<QueryText>;
    fn cursor(&self, value: String) -> crate::Result<AtlasCursor>;
    fn query_budget(&self, results: u16, bytes: u32) -> crate::Result<QueryBudget>;
    fn selector(&self, value: SymbolSelector) -> crate::Result<SymbolSelector>;
}

/// Borrow the validated UTF-8 spelling without creating another text domain.
pub trait AtlasText {
    fn as_str(&self) -> &str;
}
