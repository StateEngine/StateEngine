use crate::{Actor, RecordId};
/// The original declaration used RecordId here, which cannot represent the
/// private v8 dictionary keys of imported domain identities. Resolve a closed
/// typed target in the same transaction instead of fabricating a v7 alias.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum LegacyTarget {
    Project(se_types::ProjectId),
    Principal(Actor),
    Session(se_types::SessionId),
    Message(se_types::MessageId),
    Decision(se_types::DecisionId),
    Event(se_types::EventId),
    Record(RecordId),
}
/// Durable source disposition counts and counted import notes.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportCounts {
    #[serde(default)]
    pub deferred: u64,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub notes: std::collections::BTreeMap<String, u64>,
    pub read: u64,
    pub imported: u64,
    pub duplicate: u64,
    pub unreadable: u64,
    pub dropped_by_policy: u64,
}
