//! A compact first-turn orientation: where things live in the indexed tree
//! and which assignments the agent already holds.
use crate::EventId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A deterministic map of the indexed tree, read from the index alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepoMap {
    /// Files in the index, tests included.
    pub files: u64,
    /// The index matched the working tree when the map was read; false while
    /// it is building, catching up, or has stale files.
    pub current: bool,
    /// `[area, files]`, largest first, without tests or generated files.
    pub areas: Vec<(String, u64)>,
    /// The files most other files import.
    pub hubs: Vec<RepoHub>,
    /// False when areas or hubs were left out by count or byte budget.
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepoHub {
    pub path: String,
    /// Distinct indexed files importing this one.
    pub importers: u64,
    /// Its first top-level declarations, in file order.
    pub declarations: Vec<String>,
}

/// An open assignment the agent holds, as the store tracks it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AssignmentLink {
    pub id: EventId,
    /// `open`, `working` or `blocked`.
    pub state: String,
    /// The request's first line; absent when it was erased or unreadable,
    /// which `assignment list` reports in full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Orientation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map: Option<RepoMap>,
    /// Why `map` is absent: the index is not ready, or the map missed its
    /// time or byte budget. Never set together with `map`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_note: Option<String>,
    pub assignments: Vec<AssignmentLink>,
    /// More open assignments exist than are listed, or the list was cut short.
    pub more_assignments: bool,
}
