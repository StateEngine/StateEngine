//! Typed launch input and owned coordinator plan. No native resource, secret or
//! actor can be reconstructed from an operation DTO.
use super::{
    ProcessView, ResumeCommand,
    inputs::{Validate, bounded},
};
use crate::config_policy::{Provider, ResolvedProfile};
use schemars::JsonSchema;
use se_types::{
    AgentId, EventId, IdempotencyKey, LaunchId, LifecycleId, Named, NativePath, ProjectId,
    ProviderSessionId, Read, Result, SessionId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentLaunch {
    pub target_agent_id: Option<AgentId>,
    #[serde(default, rename = "new")]
    pub fresh: bool,
    pub model: Option<String>,
    pub task: Option<String>,
    #[serde(default = "headless")]
    pub detach: bool,
    pub idempotency_key: IdempotencyKey,
    /// Only the core's decoded CLI selection layer supplies these values.
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<String>,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_provider: Option<Provider>,
}
fn headless() -> bool {
    true
}
impl Validate for AgentLaunch {
    fn validate(&self) -> Result<()> {
        if let Some(value) = &self.model {
            bounded("model", value, 256, false)?;
        }
        if let Some(value) = &self.task {
            bounded("task", value, 16 * 1024, true)?;
        }
        if let Some(value) = &self.owner_agent {
            bounded("agent selector", value, 512, false)?;
        }
        Ok(())
    }
}
/// Finite admitted metadata, consumed by the host after its planning snapshot
/// closes. The coordinator never substitutes a different target or profile.
#[derive(Clone)]
pub struct LaunchPlan {
    pub input: AgentLaunch,
    pub project: Named<ProjectId>,
    pub owner: se_types::HumanId,
    pub agent: Named<AgentId>,
    pub cwd: NativePath,
    pub profile: se_store::Profile,
    pub resolved: ResolvedProfile,
    pub conversation: Read<ProviderSessionId>,
    pub capture: bool,
    pub control: se_store::ControlTarget,
    pub seed: EventId,
    pub replayed: bool,
    pub session: SessionId,
    pub lifecycle: LifecycleId,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LaunchResult {
    pub idempotency_key: IdempotencyKey,
    pub event_id: EventId,
    pub launch_id: LaunchId,
    pub lifecycle_id: LifecycleId,
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
    pub session_id: SessionId,
    pub provider: Provider,
    pub model: Option<String>,
    pub permission_profile: ResolvedProfile,
    pub conversation_id: ProviderSessionId,
    pub state: String,
    pub surface: String,
    pub process: ProcessView,
    pub containment: String,
    pub containment_cause: Option<String>,
    pub resume: ResumeCommand,
    pub replies: Option<super::AgentCommand>,
}
