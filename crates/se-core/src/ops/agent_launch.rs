//! Typed launch input and owned coordinator plan. No native resource, secret or
//! actor can be reconstructed from an operation DTO.
use super::{
    ProcessView, ResumeCommand,
    inputs::{Validate, bounded},
};
use schemars::JsonSchema;
use se_config::config_policy::{Provider, ResolvedProfile};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<se_types::ResumeSelection>,
    pub model: Option<String>,
    pub task: Option<String>,
    #[serde(default = "headless")]
    pub detach: bool,
    /// Explicit consent to stop the existing managed lifecycle and its jobs.
    #[serde(
        default,
        rename = "force",
        alias = "override_live",
        skip_serializing_if = "no_override"
    )]
    pub override_live: bool,
    /// Optional selection returned by the confirmation inventory. A changed
    /// target must be inspected again instead of stopping a newer session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_selection: Option<ForceSelection>,
    pub idempotency_key: IdempotencyKey,
    /// Only the core's decoded CLI selection layer supplies these values.
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<String>,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_provider: Option<Provider>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForceSelection {
    pub lifecycles: Vec<LifecycleId>,
    pub sessions: Vec<SessionId>,
}

fn headless() -> bool {
    true
}
fn no_override(value: &bool) -> bool {
    !value
}
pub use se_store::{
    ATTENDED_RECONNECT_FAILED, ATTENDED_SETUP_EXPIRED, expired_attended_setup,
    retryable_attended_setup,
};
impl AgentLaunch {
    pub fn fresh(&self) -> bool {
        !se_types::ResumeSelection::requested(self.resume.as_ref())
    }
    /// A busy target is inventoried before this launch-mode refusal. The host
    /// rechecks it before any preflight or native replacement can take effect.
    pub fn require_launch_mode(&self, provider: se_store::Provider) -> Result<()> {
        if matches!(
            provider,
            se_store::Provider::SeCode | se_store::Provider::Acp
        ) && !self.detach
        {
            return Err(se_types::SeError::invalid(
                "protocol launch mode",
                "headless launch with --detach, or --force for a forced headless relaunch",
            ));
        }
        Ok(())
    }

    /// Route syntax is not request identity: CLI selectors and MCP IDs bind to
    /// the same admitted agent. Keep every other caller argument unchanged.
    pub fn intent(&self, selected: &AgentId) -> Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| crate::scope::unreadable("launch intent", &e.to_string()))?;
        value["target_agent_id"] = serde_json::json!(selected);
        value["selected_agent"] = serde_json::json!(selected);
        // Explicit false and omission make the same fresh request, including
        // a CLI retry printed for a pending MCP launch.
        if self.fresh()
            && let Some(object) = value.as_object_mut()
        {
            let _ = object.remove("resume");
        }
        Ok(value)
    }
}
impl LaunchPlan {
    /// Preserve the preflight decision when replanning after a forced stop.
    pub fn prepare_replacement(
        &mut self,
        original: &Self,
        fallback: Option<Read<ProviderSessionId>>,
        new_conversation: bool,
    ) -> Result<()> {
        if original.profile != self.profile || original.resolved != self.resolved {
            return Err(se_types::SeError::invalid(
                "takeover profile",
                "the saved launch profile changed during takeover; retry with its current profile",
            ));
        }
        if new_conversation {
            self.start_new_conversation("Forced relaunch preserved the previous history and starts a new conversation because the previous service was forcibly retired or final capture remained unavailable.".into());
        } else if let Some(Read::Absent { checked }) = fallback {
            self.start_new_conversation(checked);
        }
        Ok(())
    }

    /// Retain self-launch authority only for the replacement session.
    pub fn successor_admission(&self, mut admission: se_store::Admission) -> se_store::Admission {
        if matches!(&admission.actor, se_store::Actor::Agent(agent) if agent == &self.agent.id) {
            admission.session = Some(self.session.clone());
        }
        admission
    }

    pub fn details(&self) -> se_types::LaunchDetails {
        se_types::LaunchDetails {
            provider: self.profile.provider.into(),
            model: self
                .input
                .model
                .clone()
                .or_else(|| self.profile.model.clone()),
            permission_profile: self.resolved.name.clone(),
            permission: match self.resolved.sandbox {
                se_config::config_policy::EffectiveSandbox::ReadOnly => "read-only",
                se_config::config_policy::EffectiveSandbox::WorkspaceWrite => "workspace-write",
                se_config::config_policy::EffectiveSandbox::Bypass => "bypass",
            }
            .into(),
            network: self.resolved.network,
            resumed: matches!(self.conversation, Read::Present { .. }),
            conversation: self.conversation.clone(),
            mail_notifications: Read::Unknown {
                what: "launch preparation has not connected the provider".into(),
            },
        }
    }
    pub fn start_new_conversation(&mut self, reason: String) {
        self.conversation = Read::Absent {
            checked: reason.clone(),
        };
        self.saved_conversation_age = Read::Absent { checked: reason };
    }
}
impl Validate for AgentLaunch {
    fn validate(&self) -> Result<()> {
        if let Some(selection) = &self.force_selection
            && (!self.override_live
                || selection.lifecycles.len() > 4096
                || selection.sessions.len() > 4096)
        {
            return Err(se_types::SeError::invalid(
                "force selection",
                "a bounded confirmation selection supplied with force",
            ));
        }
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
    /// Native authenticated origin; never supplied by a local operation DTO.
    pub remote: Option<se_types::remote::RemoteAttribution>,
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
    pub ephemeral_one_shot: bool,
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
    #[serde(default = "se_types::LaunchDetails::unobserved_mail")]
    pub mail_notifications: Read<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_policy_notice: Option<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_sessions: Vec<SessionId>,
    #[serde(default, skip_serializing_if = "no_override")]
    pub new_conversation: bool,
    pub scope: String,
    /// An unavailable diagnostic inventory is not an observation of zero jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_failure: Option<String>,
    /// Externally owned services whose jobs were not stopped by this operation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_services: Vec<String>,
    /// Jobs observed before stop and separately observed no longer executing
    /// afterward. Later spawns are not individually listed by this receipt.
    pub jobs_stopped: Vec<TakeoverJob>,
    /// Observed descendants still live outside the stopped native scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jobs_remaining: Vec<TakeoverJob>,
    /// Recorded jobs whose individual post-stop observation was unreadable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jobs_unproved: Vec<TakeoverJob>,
    pub witness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TakeoverJob {
    pub pid: u32,
    pub command: String,
}
