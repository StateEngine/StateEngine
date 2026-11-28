//! Structural facts of a turn an external harness or owner client publishes.
//! Prose travels separately as the event's one erasable body.
use se_types::{AgentId, SessionId};

/// Token counts as the caller reported them. `cost_usd` is present only when
/// the caller reported a cost; it is never derived.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TurnUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: Option<f64>,
}

/// Change counts; the changed paths are prose in the erasable body.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DiffCounts {
    pub files_changed: u64,
    pub insertions: u64,
    pub deletions: u64,
}

/// Where a nested turn sits: the parent session it ran under, the harness's own
/// nested agent label, and its depth (1 is a direct child).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TurnNesting {
    pub parent_session: SessionId,
    pub nested_agent: String,
    pub depth: u32,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PublishedTurn {
    pub agent: AgentId,
    pub session: SessionId,
    pub conversation: String,
    pub harness: String,
    pub model_provider: String,
    pub model: String,
    pub vendor_turn: String,
    pub occurred_at_us: i64,
    pub role: crate::Role,
    pub body_omitted_bytes: u64,
    /// SHA-256 of the complete content. Erasure removes it with the body.
    pub content_sha256: Option<[u8; 32]>,
    /// True when the stored body is the complete content and hashes to the digest.
    pub content_verified: bool,
    pub usage: Option<TurnUsage>,
    pub diff: Option<DiffCounts>,
    pub nesting: Option<TurnNesting>,
}
