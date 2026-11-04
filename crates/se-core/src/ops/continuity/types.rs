use crate::ops::{MessageRow, WorkingStateValue, inputs::Validate};
use schemars::JsonSchema;
use se_types::{AgentId, Cursor, Named, Page, ProjectId, Read, Result, SeError, SessionId, Window};
use serde::{Deserialize, Serialize};
pub const DEFAULT_BYTES: u32 = 32768;
pub fn default_limit() -> u16 {
    20
}
pub fn default_bytes() -> u32 {
    DEFAULT_BYTES
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    #[serde(default = "default_limit")]
    pub limit: u16,
    #[serde(default)]
    pub governing_cursor: Option<Cursor>,
    #[serde(default)]
    pub since: Option<Cursor>,
    #[serde(default = "default_bytes")]
    pub byte_budget: u32,
    #[serde(skip)]
    #[schemars(skip)]
    pub preview_agent: Option<AgentId>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionContextRequest {
    #[serde(default)]
    pub governing_cursor: Option<Cursor>,
    #[serde(default = "default_limit")]
    pub limit: u16,
    #[serde(default)]
    pub since: Option<Cursor>,
    #[serde(default = "default_bytes")]
    pub byte_budget: u32,
}
fn bytes(value: u32) -> Result<()> {
    if !(1024..=1048576).contains(&value) {
        return Err(SeError::invalid("byte_budget", "1024..1048576 UTF-8 bytes"));
    }
    Ok(())
}
impl Validate for Resume {
    fn validate(&self) -> Result<()> {
        if !(1..=100).contains(&self.limit) {
            return Err(SeError::invalid("limit", "1..100"));
        }
        bytes(self.byte_budget)
    }
}
impl Validate for SessionContextRequest {
    fn validate(&self) -> Result<()> {
        if !(1..=100).contains(&self.limit) {
            return Err(SeError::invalid("limit", "1..100"));
        }
        bytes(self.byte_budget)
    }
}
impl Resume {
    pub fn validate(&self) -> Result<()> {
        Validate::validate(self)
    }
}
impl SessionContextRequest {
    pub fn validate(&self) -> Result<()> {
        Validate::validate(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContinuityPrincipal {
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
    pub session_id: Option<SessionId>,
    pub preview: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Budget {
    pub limit_bytes: u32,
    pub used_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RequiredRead {
    pub kind: String,
    pub id: String,
    pub why: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GoverningDecision {
    pub id: se_types::DecisionId,
    pub key: String,
    pub statement: String,
    pub ratified_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Decisions {
    pub next_cursor: Option<Cursor>,
    pub governing: Vec<GoverningDecision>,
    pub pending: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecentTurn {
    pub event_id: se_types::EventId,
    pub at: String,
    pub role: String,
    pub preview: String,
    pub complete: bool,
    pub bytes: u64,
    pub command: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Omission {
    pub section: String,
    pub count: Option<u64>,
    pub reason: String,
    pub tool: String,
    pub command: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContinuityWorkingState {
    #[serde(flatten)]
    pub value: WorkingStateValue,
    pub complete: bool,
    pub bytes: u64,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResumeOutput {
    pub schema_version: u8,
    pub resume_status: String,
    pub principal: ContinuityPrincipal,
    pub generated_at: String,
    pub since: Option<Cursor>,
    pub complete: bool,
    pub budget: Budget,
    pub working_state: Read<ContinuityWorkingState>,
    pub unread: Page<MessageRow>,
    pub required_reads: Vec<RequiredRead>,
    pub decisions: Decisions,
    pub recent_turns: Vec<RecentTurn>,
    #[serde(flatten, default)]
    pub transcript: crate::ops::transcript::View,
    pub code_changes: Option<Vec<serde_json::Value>>,
    pub omissions: Vec<Omission>,
    pub attention: Vec<String>,
    pub cursor: Cursor,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContextDisplayIdentity {
    pub agent_id: AgentId,
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub neutral: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContinuitySummary {
    pub rows: u64,
    pub latest_ts: Option<String>,
}
/// Retains the existing SE Code decoder's field names and contract literal.
/// Its complete model input is assembled from the same read set as Resume.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SessionContextOutput {
    pub schema_version: u8,
    pub contract: String,
    pub packet_id: String,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub session_id: SessionId,
    pub source_cli: String,
    pub generated_at: String,
    pub identity: ContextDisplayIdentity,
    pub harness: String,
    pub model: Option<String>,
    pub conversation: String,
    pub assembled_model_input: String,
    pub byte_size: u64,
    pub truncated: bool,
    pub continuity: Window,
    pub continuity_summary: ContinuitySummary,
    pub warnings: Vec<String>,
    pub failures: Vec<se_types::ErrorBody>,
    pub cursor: Cursor,
}
