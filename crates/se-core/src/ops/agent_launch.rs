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
mod pending;
pub use pending::{LaunchPending, LaunchPendingState, LaunchReply};

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
    /// Explicit consent to stop the existing managed lifecycle and its jobs.
    #[serde(default, skip_serializing_if = "no_override")]
    pub override_live: bool,
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
fn no_override(value: &bool) -> bool {
    !value
}
/// A window that never connected may be replaced by an ordinary launch after
/// its credentials were revoked. This is not an activated conversation.
pub const ATTENDED_SETUP_EXPIRED: &str = "attended setup exceeded its activation deadline";
pub const ATTENDED_RECONNECT_FAILED: &str =
    "expired attended setup replacement failed before activation";
pub fn expired_attended_setup(record: &se_store::ProjectionRecord) -> bool {
    attended_setup_reason(record) == Some(ATTENDED_SETUP_EXPIRED)
}
pub fn retryable_attended_setup(record: &se_store::ProjectionRecord) -> bool {
    matches!(
        attended_setup_reason(record),
        Some(ATTENDED_SETUP_EXPIRED | ATTENDED_RECONNECT_FAILED)
    )
}
fn attended_setup_reason(record: &se_store::ProjectionRecord) -> Option<&str> {
    if record.current.revision.value.get() != 2
        || !matches!(
            &record.original.as_deref().unwrap_or(&record.current).body,
            se_store::EventBody::SessionPrepared {
                provider: se_store::Provider::Claude,
                surface: Some(se_store::SessionSurface::Window),
                ..
            }
        )
    {
        return None;
    }
    match &record.current.body {
        se_store::EventBody::SessionRevoked {
            reason: se_store::StoredText::Present(reason),
            ..
        } => Some(reason),
        _ => None,
    }
}
impl AgentLaunch {
    /// Route syntax is not request identity: CLI selectors and MCP IDs bind to
    /// the same admitted agent. Keep every other caller argument unchanged.
    pub fn intent(&self, selected: &AgentId) -> Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| crate::scope::unreadable("launch intent", &e.to_string()))?;
        value["target_agent_id"] = serde_json::json!(selected);
        value["selected_agent"] = serde_json::json!(selected);
        Ok(value)
    }
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
    pub channel_resume: Option<(se_store::channel::ChannelId, se_store::channel::ActionId)>,
    pub project: Named<ProjectId>,
    pub owner: se_types::HumanId,
    pub agent: Named<AgentId>,
    pub cwd: NativePath,
    pub profile: se_store::Profile,
    pub resolved: ResolvedProfile,
    pub conversation: Read<ProviderSessionId>,
    pub saved_conversation_age: Read<SavedConversationAge>,
    pub capture: bool,
    pub control: se_store::ControlTarget,
    pub seed: EventId,
    pub replayed: bool,
    pub session: SessionId,
    pub lifecycle: LifecycleId,
}
/// Age of the saved session selected for this conversation, not an inferred
/// provider conversation creation time. Measured when the launch is planned.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SavedConversationAge {
    pub session_started_at: String,
    pub age_seconds: Read<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LaunchResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secode_binding: Option<Read<super::SecodeBindingView>>,
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
    pub resumed: bool,
    pub saved_conversation_age: Read<SavedConversationAge>,
    pub state: String,
    pub surface: String,
    pub process: ProcessView,
    pub containment: String,
    pub containment_cause: Option<String>,
    pub resume: ResumeCommand,
    pub replies: Option<super::AgentCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TakeoverReport {
    pub previous_session: SessionId,
    pub scope: String,
    /// Jobs observed before stop and separately observed no longer executing
    /// afterward. Later spawns are not individually listed by this receipt.
    pub jobs_stopped: Vec<TakeoverJob>,
    /// Observed descendants still live outside the stopped native scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jobs_remaining: Vec<TakeoverJob>,
    pub witness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TakeoverJob {
    pub pid: u32,
    pub command: String,
}
