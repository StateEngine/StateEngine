//! Exact agent stop receipts. An empty diagnostic list is never an empty scope.
use super::{
    ProcessView,
    inputs::{Validate, bounded},
};
use crate::config_policy::Provider;
use schemars::JsonSchema;
use se_types::{
    AgentId, EventId, IdempotencyKey, LaunchId, LifecycleId, Named, ProjectId, Result, SeError,
    SessionId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentStop {
    pub target_agent_id: Option<AgentId>,
    pub idempotency_key: IdempotencyKey,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<String>,
    #[serde(skip)]
    #[schemars(skip)]
    pub all: bool,
    #[serde(skip)]
    #[schemars(skip)]
    pub release: bool,
}
impl Validate for AgentStop {
    fn validate(&self) -> Result<()> {
        if let Some(value) = &self.owner_agent {
            bounded("agent selector", value, 512, false)?;
        }
        if self.all
            && (self.release || self.owner_agent.is_some() || self.target_agent_id.is_some())
        {
            return Err(SeError::invalid(
                "stop selection",
                "one target, or --all without --release",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StopTarget {
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
    pub session_id: Option<SessionId>,
    pub launch_id: Option<LaunchId>,
    pub provider: Provider,
    pub process: Option<ProcessView>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StopCapture {
    pub flushed: bool,
    pub last_event_id: Option<EventId>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StopResume {
    pub state: String,
    pub reason: Option<String>,
    pub conversation_id: Option<String>,
    pub provider: Provider,
    pub model: Option<String>,
    pub command: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OwnershipRelease {
    pub lifecycle: LifecycleId,
    pub generation: u64,
    pub revision: u64,
    pub scope: String,
    pub remaining: Vec<ProcessView>,
    pub released_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StopWitness {
    pub state: String,
    pub method: Option<String>,
    pub observed_at: Option<String>,
    pub detail: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentStopResult {
    pub target: StopTarget,
    pub result: String,
    pub event_id: Option<EventId>,
    pub method: Option<String>,
    pub witness: StopWitness,
    pub population: String,
    pub population_reason: Option<String>,
    pub ownership_release: Option<OwnershipRelease>,
    pub remaining: Vec<ProcessView>,
    pub enumeration: String,
    pub capture: StopCapture,
    pub resume: StopResume,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StopResult {
    pub idempotency_key: IdempotencyKey,
    pub receipt: String,
    pub scope: String,
    pub result: String,
    pub complete: bool,
    pub event_id: Option<EventId>,
    pub target: Option<StopTarget>,
    pub method: Option<String>,
    pub witness: Option<StopWitness>,
    pub population: Option<String>,
    pub population_reason: Option<String>,
    pub ownership_release: Option<OwnershipRelease>,
    pub remaining: Option<Vec<ProcessView>>,
    pub enumeration: Option<String>,
    pub capture: Option<StopCapture>,
    pub resume: Option<StopResume>,
    pub stops: Option<Vec<AgentStopResult>>,
}
