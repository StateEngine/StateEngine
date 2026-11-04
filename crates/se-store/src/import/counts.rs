//! Durable source disposition counts and counted import notes.
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
