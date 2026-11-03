use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProcessView {
    pub pid: u32,
    pub started_at: String,
    pub exe: String,
    pub machine_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Witness {
    pub state: WitnessState,
    pub method: String,
    pub observed_at: String,
    pub detail: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WitnessState {
    Witnessed,
    Unknown,
    Failed,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FileOutcome {
    Written,
    Removed,
    Unchanged,
    AlreadyAbsent,
    ConflictKept,
    Unreadable,
    Pending,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FileEffect {
    pub path: String,
    pub outcome: FileOutcome,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DirectoryOutcome {
    Removed,
    AlreadyAbsent,
    NotEmptyPreserved,
    Unreadable,
    Unsafe,
    Pending,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DirectoryEffect {
    pub path: String,
    pub outcome: DirectoryOutcome,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct IntegrationEffect {
    pub path: String,
    pub entry: String,
    #[serde(rename = "outcome")]
    pub action: FileOutcome,
    pub witness: Witness,
}
