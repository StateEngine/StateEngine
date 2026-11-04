//! Search modes and mixed results; one typed result family for every consumer.
use super::*;

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    Exact,
    Literal,
    Phrase,
    Broad,
    Related,
}
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SearchOrder {
    #[default]
    Relevance,
    Recency,
}
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AtlasFormat {
    #[default]
    Compact,
    Json,
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum AtlasTarget {
    Symbol(SymbolSelector),
    File(RelativePath),
    Commit(GitObjectId),
    Record(RecordKey),
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct CommitHit {
    pub oid: GitObjectId,
    pub author: String,
    /// Git author time, not Atlas observation time.
    pub author_unix_ms: i64,
    pub subject: String,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum HitTarget {
    Code(CodeHit),
    Record(RecordHit),
    Commit(CommitHit),
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct HitReason {
    pub mode: SearchMode,
    pub match_tier: u8,
    pub last_touch_unix_ms: Option<i64>,
    pub edited_by: Option<AgentId>,
    /// Viewer-filtered count, never the unrestricted cached count.
    pub cited_messages: u32,
    pub text_only: bool,
    pub related: bool,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct SearchHit {
    pub target: HitTarget,
    pub reason: HitReason,
    pub rank_version: u32,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum ReferenceHit {
    Code(Reference),
    Record(RecordHit),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchResults {
    pub mode: SearchMode,
    pub fallback_from: Option<SearchMode>,
    pub page: crate::Page<SearchHit>,
    /// None is unknown; zero is a counted complete candidate range.
    pub truncated_candidates: Option<u64>,
}
