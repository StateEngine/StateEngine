use super::{AgentRow, Named, NextStep, ProcessView, ProjectView};
use schemars::JsonSchema;
use se_types::{AgentId, EventId, Page, ProjectId, Read, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SetupState {
    Configured,
    NotSetUp,
    Unreadable,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SetupView {
    pub state: SetupState,
    pub home: String,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceSample {
    pub self_voluntary_switches: Option<u64>,
    pub self_involuntary_switches: Option<u64>,
    pub cpu_user_us: u64,
    pub cpu_system_us: u64,
    pub rss_bytes: u64,
    pub sampled_at: String,
    pub method: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HostDetachment {
    WindowsBreakaway,
    UserManagerUnit,
    SessionOnly,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeView {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detachment: Option<HostDetachment>,
    pub host: Option<String>,
    pub process: Option<ProcessView>,
    pub generation: Option<u64>,
    pub endpoint: Option<String>,
    pub version: Option<String>,
    pub observed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceSample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_unavailable: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovalView {
    pub project: Named<ProjectId>,
    pub root: String,
    pub removed_at: String,
    pub event_id: EventId,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalView {
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
    pub session_id: SessionId,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InboxCounts {
    pub owner_unread: Option<u64>,
    pub self_unread: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionCounts {
    pub pending: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaptureView {
    pub state: String,
    pub last_turn_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasView {
    pub state: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PendingFact {
    pub what: String,
    pub since: Option<String>,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProjectSummary {
    pub id: ProjectId,
    pub name: String,
    pub root: Option<String>,
    pub agents_running: Option<u64>,
    pub owner_unread: Option<u64>,
    pub errors: Vec<se_types::ErrorBody>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StatusOutput {
    pub scope: String,
    pub generated_at: String,
    pub version: String,
    pub setup: SetupView,
    pub runtime: RuntimeView,
    pub project: Read<ProjectView>,
    pub removal: Option<RemovalView>,
    pub principal: Option<PrincipalView>,
    pub agents: Option<Page<AgentRow>>,
    pub inbox: InboxCounts,
    pub decisions: DecisionCounts,
    pub capture: CaptureView,
    pub atlas: AtlasView,
    pub pending: Vec<PendingFact>,
    pub projects: Option<Page<ProjectSummary>>,
    pub next: NextStep,
}
