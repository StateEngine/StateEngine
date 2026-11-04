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
    pub body: Option<HitBody>,
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

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum BodyOrigin {
    /// Live, independently verified range; a range hash never implies a whole
    /// file revision. matches_index=None means the comparison was unavailable.
    LiveSource {
        file: FileId,
        path: RelativePath,
        span: Span,
        range_hash: ContentHash,
        content_hash: Option<ContentHash>,
        matches_index: Option<bool>,
    },
    /// Core reread the authoritative record after checking viewer access.
    AuthoritativeRecord(RecordPointer),
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "HitBodyWire")]
pub struct HitBody {
    pub origin: BodyOrigin,
    pub text: String,
    pub complete: bool,
}
impl HitBody {
    pub fn new(origin: BodyOrigin, text: String, complete: bool) -> crate::Result<Self> {
        if text.len() > 12 * 1024 || text.lines().count() > 40 {
            return Err(crate::SeError::invalid(
                "Atlas hit body",
                "at most 40 lines and 12 KiB; the response shares the same 12 KiB full-body budget",
            ));
        }
        Ok(Self {
            origin,
            text,
            complete,
        })
    }
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct HitBodyWire {
    origin: BodyOrigin,
    text: String,
    complete: bool,
}
impl TryFrom<HitBodyWire> for HitBody {
    type Error = crate::SeError;
    fn try_from(value: HitBodyWire) -> crate::Result<Self> {
        Self::new(value.origin, value.text, value.complete)
    }
}
