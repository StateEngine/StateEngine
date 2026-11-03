use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct NextStep {
    pub text: String,
    pub command: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Build {
    pub commit: Option<String>,
    pub provenance: Provenance,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    Observed,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VersionOutput {
    pub version: String,
    pub build: Build,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HelpOutput {
    pub path: Vec<String>,
    pub usage: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OpSchema {
    pub name: String,
    pub metadata: serde_json::Value,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SchemaCatalogue {
    pub api: String,
    pub build: Build,
    pub ops: Vec<OpSchema>,
    pub families: Vec<String>,
    pub errors: Vec<serde_json::Value>,
}
