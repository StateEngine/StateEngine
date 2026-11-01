use super::{Named, Provider, ReceiptAuthority, WriteReceipt};
use crate::{AgentId, ProjectId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentAction {
    Create,
    Rename,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentOutcome {
    Created,
    Existing,
    Renamed,
    Unchanged,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentReceiptValue {
    pub id: AgentId,
    pub name: String,
    pub provider: Provider,
    pub model: Option<String>,
    pub profile: String,
}
/// This receipt family cannot claim it launched a process.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(try_from = "bool", into = "bool")]
pub struct NoProcessStarted;
impl From<NoProcessStarted> for bool {
    fn from(_: NoProcessStarted) -> Self {
        false
    }
}
impl TryFrom<bool> for NoProcessStarted {
    type Error = crate::SeError;
    fn try_from(value: bool) -> crate::Result<Self> {
        if value {
            return Err(crate::SeError::invalid(
                "process_started",
                "false for agent identity receipts",
            ));
        }
        Ok(Self)
    }
}
impl JsonSchema for NoProcessStarted {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "NoProcessStarted".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"boolean", "const":false})
    }
}
/// se.agent-receipt/v1 payload. Identity creation/rename never launches a process.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentReceipt {
    #[serde(flatten)]
    pub commit: WriteReceipt,
    pub action: AgentAction,
    pub outcome: AgentOutcome,
    pub agent: AgentReceiptValue,
    pub previous_name: Option<String>,
    pub process_started: NoProcessStarted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigStorage {
    AgentRecord,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConfigPreviousSource {
    Stored,
    Default,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigPreviousValue {
    pub value: serde_json::Value,
    pub source: ConfigPreviousSource,
}
/// Store-backed se.config-receipt/v1 branch for agent.<A>.{model,profile,can-create}.
/// File-only general settings have no store writer and cannot use this payload.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentConfigReceipt {
    #[serde(flatten)]
    pub commit: WriteReceipt,
    pub storage: ConfigStorage,
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
    pub key: String,
    pub previous: ConfigPreviousValue,
    pub value: serde_json::Value,
    pub revision: u64,
    pub current_revision: u64,
    pub authority: ReceiptAuthority,
}
