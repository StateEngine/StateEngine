//! Transient committed-record feed and pointers. Bodies are never cache values.
use super::*;
use crate::{HumanId, Result, SeError};

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct RecordKey(String);
impl RecordKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(SeError::invalid(
                "Atlas record key",
                "1..256 bytes without controls",
            ));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for RecordKey {
    type Error = SeError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}
impl From<RecordKey> for String {
    fn from(value: RecordKey) -> Self {
        value.0
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// Retained only to decode pointers from caches created before ledger retirement.
    #[schemars(skip)]
    Decision,
    Message,
    Working,
    Edit,
    Commit,
}

/// Canonical principal keys; display names never confer visibility.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AtlasPrincipal {
    Agent(AgentId),
    Human(HumanId),
    /// Attribution only: remote grants do not authorize Atlas queries.
    Remote(crate::remote::RemotePrincipalId),
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct AtlasActor {
    pub principal: AtlasPrincipal,
    pub name: String,
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RecordVisibility {
    Project,
    /// None means core must check access. It never means project-visible.
    Restricted {
        audience: Option<Vec<AtlasPrincipal>>,
    },
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum MentionTarget {
    File(RelativePath),
    Symbol(SymbolId),
    Identifier(QueryText),
    Commit(GitObjectId),
    Record(RecordKey),
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct RecordPointer {
    pub key: RecordKey,
    pub kind: RecordKind,
    pub source_event: EventId,
}

/// Constructed only from a committed, project-scoped core feed. The writer
/// tokenizes `body`, then drops it; only core may render an authorized body line.
#[derive(Debug)]
pub struct FeedRecord {
    pub pointer: RecordPointer,
    pub project: ProjectId,
    pub actor: Option<AtlasActor>,
    pub occurred_unix_ms: i64,
    pub title: String,
    pub visibility: RecordVisibility,
    pub body: String,
    pub body_truncated: bool,
    pub mentions: Vec<MentionTarget>,
}
impl FeedRecord {
    pub fn validate(&self) -> Result<()> {
        let bad_audience = matches!(&self.visibility,
            RecordVisibility::Restricted { audience: Some(keys) }
            if keys.len() > 32 || keys.windows(2).any(|p| p[0] >= p[1]));
        if self.title.len() > 160
            || self.body.len() > 65536
            || self.mentions.len() > 256
            || self
                .actor
                .as_ref()
                .is_some_and(|actor| actor.name.len() > 160)
            || serde_json::to_vec(&self.mentions)
                .map_err(|e| SeError::invalid("Atlas mentions", &e.to_string()))?
                .len()
                > 32768
            || bad_audience
        {
            return Err(SeError::invalid(
                "Atlas record feed",
                "title <=160 bytes, body <=64 KiB, <=256 mentions and <=32 sorted distinct audience keys",
            ));
        }
        Ok(())
    }
}
#[derive(Debug)]
pub enum RecordFeedChange {
    Upsert(FeedRecord),
    /// Deletion is a committed core fact, never inferred from a failed read.
    Remove {
        project: ProjectId,
        key: RecordKey,
    },
}
/// One bounded feed chunk. `after` and `through` are authoritative event IDs,
/// never Atlas generations; cursor advancement and changes commit together.
#[derive(Debug)]
pub struct RecordFeed {
    pub project: ProjectId,
    pub after: Option<EventId>,
    pub through: EventId,
    pub changes: Vec<RecordFeedChange>,
    pub complete: bool,
}
impl RecordFeed {
    pub fn validate(&self) -> Result<()> {
        if self.changes.len() > 64 {
            return Err(SeError::invalid("Atlas record feed", "at most 64 changes"));
        }
        let mut bytes = 0usize;
        let mut metadata = 0usize;
        for change in &self.changes {
            match change {
                RecordFeedChange::Upsert(record) => {
                    record.validate()?;
                    if record.project != self.project {
                        return Err(SeError::invalid(
                            "Atlas record feed",
                            "one verified project",
                        ));
                    }
                    bytes += record.body.len();
                    metadata += record.title.len();
                    metadata += serde_json::to_vec(&record.mentions)
                        .map_err(|e| SeError::invalid("Atlas mentions", &e.to_string()))?
                        .len()
                        + serde_json::to_vec(&record.actor)
                            .map_err(|e| SeError::invalid("Atlas actor", &e.to_string()))?
                            .len()
                        + serde_json::to_vec(&record.visibility)
                            .map_err(|e| SeError::invalid("Atlas visibility", &e.to_string()))?
                            .len()
                        + record.pointer.key.as_str().len()
                        + record.pointer.source_event.as_str().len();
                }
                RecordFeedChange::Remove { project, .. } if project != &self.project => {
                    return Err(SeError::invalid(
                        "Atlas record feed",
                        "one verified project",
                    ));
                }
                _ => (),
            }
        }
        if bytes > 65536 || metadata > 32768 {
            return Err(SeError::invalid(
                "Atlas record feed",
                "at most 64 KiB transient text and 32 KiB metadata per chunk",
            ));
        }
        Ok(())
    }
}

/// A candidate only. Core rechecks visibility and rereads the authority before
/// constructing this rendered hit or including its contribution in any count.
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct RecordHit {
    pub pointer: RecordPointer,
    pub actor: Option<AtlasActor>,
    pub occurred_unix_ms: i64,
    pub line: String,
    pub body_truncated: bool,
    pub mentions: Vec<MentionTarget>,
}
