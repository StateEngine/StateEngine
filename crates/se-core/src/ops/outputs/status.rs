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
    WindowsBroker,
    UserManagerUnit,
    SessionOnly,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeView {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detachment: Option<HostDetachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detachment_notice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawner: Option<SpawnerView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawner_cleanup: Option<SpawnerCleanupView>,
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
pub struct SpawnerView {
    pub pid: u32,
    pub birth: String,
    pub state: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpawnerCleanupView {
    pub generation: u64,
    pub complete: bool,
    pub sessions: Vec<SpawnerCleanupSession>,
    pub pending: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpawnerCleanupSession {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
    pub lifecycle: se_types::LifecycleId,
    pub stopped: bool,
    pub reason: Option<String>,
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
pub struct CaptureView {
    pub state: String,
    pub last_turn_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasView {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<se_types::code::IndexSummary>,
    /// History is unavailable until its cold-child cost gate is qualified.
    #[serde(default = "unavailable_history")]
    pub history: String,
}
fn unavailable_history() -> String {
    "unavailable".into()
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
    pub capture: CaptureView,
    pub atlas: AtlasView,
    pub pending: Vec<PendingFact>,
    pub projects: Option<Page<ProjectSummary>>,
    pub next: NextStep,
}
