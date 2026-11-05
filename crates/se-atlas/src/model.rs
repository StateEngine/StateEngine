// Shared code DTOs have one identity across core, host and Atlas.
use se_types::ProjectId;
pub use se_types::code::{
    Accuracy, Answer, AtlasCursor, AtlasJobId, AtlasPrincipal, AuthorHint, BulkChange, BulkReason,
    ChangeId, ChangeKind, CodeChange, CodeEdit, CodeHit, CodePointer, CommitHit, ContentHash,
    Coverage, CoverageReason, Dependent, DependentCount, FileCoverage, FileId, FindMethod,
    Generation, GrammarPages, HitReason, HitTarget, Impact, ImpactHop, IndexState, IndexSummary,
    Language, MemoryBudget, MentionTarget, Outline, OutlineSymbol, Position, QueryBudget,
    QueryText, RecordHit, RecordKey, RecordKind, RecordPointer, RecordVisibility, Reference,
    ReferenceHit, ReferenceKind, RelativePath, SearchHit, SnapshotFreshness, Span,
    SurfaceAtlasState, SymbolId, SymbolKind,
};
pub use se_types::{AtlasRootId as RootId, IndexEpochId as CacheEpoch};
use std::{path::PathBuf, time::Duration};

pub const ANONYMOUS_BYTES: u32 = 13_000_000;
pub const SQL_QUERY_BYTES: u32 = 603_082;
pub const PARSER_BYTES: u32 = 12_000_000;
pub const QUEUE_BYTES: u32 = 50_000;
pub const ADAPTER_BYTES: u32 = 200_000;
pub const ALLOCATOR_SLACK_BYTES: u32 = 146_918;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CacheLocation {
    pub directory: PathBuf,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachePointer {
    pub schema: u32,
    pub project: ProjectId,
    pub root: RootId,
    pub epoch: CacheEpoch,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GitMetadataRegistration {
    pub physical_git_directory: PathBuf,
    pub physical_common_directory: PathBuf,
    pub git_directory_identity: [u8; 32],
    pub common_directory_identity: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RootRegistration {
    pub project: ProjectId,
    pub root: RootId,
    pub canonical_source_root: PathBuf,
    pub cache: CacheLocation,
    pub git_metadata: Option<GitMetadataRegistration>,
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
