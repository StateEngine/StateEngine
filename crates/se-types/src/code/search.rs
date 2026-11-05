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

/// A reverse dependency edge from the queried file toward an importing file.
/// Byte offsets belong to the indexed importer's revision; line coordinates
/// may be unavailable, so no synthetic source Span is constructed.
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct FileImpactHop {
    pub from: FileId,
    pub to: FileId,
    pub site: CodePointer,
    pub start_byte: u64,
    pub end_byte: u64,
    pub accuracy: Accuracy,
}

/// Counts describe this bounded live-source scan, not an entire unseen tree.
#[derive(
    Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TextSearchStats {
    pub scanned_files: u32,
    pub matching_files: u32,
    pub binary_files: u32,
    pub non_utf8_files: u32,
    pub oversized_files: u32,
    pub changed_files: u32,
    pub unavailable_files: u32,
    pub time_limited_files: u32,
    pub line_limited_files: u32,
    pub omitted_matches: u64,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(try_from = "SearchResultsWire")]
pub struct SearchResults {
    pub mode: SearchMode,
    pub fallback_from: Option<SearchMode>,
    pub page: crate::Page<SearchHit>,
    /// None is unknown; zero is a counted complete candidate range.
    pub truncated_candidates: Option<u64>,
    pub full: bool,
    /// Whole bodies omitted to preserve the shared response budget.
    pub bodies_omitted: u16,
    pub text: Option<TextSearchStats>,
}
impl SearchResults {
    pub fn validate(&self) -> crate::Result<()> {
        let body_bytes = self
            .page
            .items()
            .iter()
            .filter_map(|hit| hit.body.as_ref())
            .map(|body| body.text.len())
            .sum::<usize>();
        if body_bytes > 12 * 1024
            || (self.full
                && serde_json::to_vec(self)
                    .map_err(|e| crate::SeError::invalid("Atlas full response", &e.to_string()))?
                    .len()
                    > 12 * 1024)
        {
            return Err(crate::SeError::invalid(
                "Atlas full response",
                "at most 12 KiB across the response; omit whole bodies with bodies_omitted stated",
            ));
        }
        Ok(())
    }
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchResultsWire {
    mode: SearchMode,
    fallback_from: Option<SearchMode>,
    page: crate::Page<SearchHit>,
    truncated_candidates: Option<u64>,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    bodies_omitted: u16,
    #[serde(default)]
    text: Option<TextSearchStats>,
}
impl TryFrom<SearchResultsWire> for SearchResults {
    type Error = crate::SeError;
    fn try_from(value: SearchResultsWire) -> crate::Result<Self> {
        let result = Self {
            mode: value.mode,
            fallback_from: value.fallback_from,
            page: value.page,
            truncated_candidates: value.truncated_candidates,
            full: value.full,
            bodies_omitted: value.bodies_omitted,
            text: value.text,
        };
        result.validate()?;
        Ok(result)
    }
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

#[path = "cursor.rs"]
mod cursor;
pub use cursor::*;
