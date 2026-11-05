use schemars::JsonSchema;
use se_types::{Named, ProjectId, WriteReceipt};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MoveOutput {
    pub commit: WriteReceipt,
    pub project: Named<ProjectId>,
    /// The registered roots before the move, as displayed paths.
    pub from: Vec<String>,
    pub to: String,
    /// The git identity the move was proven against, from the record made at
    /// `se init`: the recorded HEAD the target must contain, and its branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}
