use super::ProcessView;
use schemars::JsonSchema;
use se_config::config_policy::Provider;
use se_types::{AgentId, Read, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SessionView {
    pub state: String,
    /// Immutable session projection state, separate from current native life.
    pub recorded_state: Option<String>,
    #[serde(default = "unobserved_session_process")]
    pub process_state: Read<String>,
    #[serde(default = "unobserved_session_process")]
    pub liveness: Read<String>,
    #[serde(flatten, default)]
    pub transcript: crate::ops::transcript::View,
    pub session_id: Option<SessionId>,
    pub launch_id: Option<se_types::LaunchId>,
    pub surface: Option<String>,
    pub process: Option<ProcessView>,
    pub since: Option<String>,
    pub observed_at: Option<String>,
    pub containment: Option<String>,
    pub containment_cause: Option<String>,
}
fn unobserved_session_process() -> Read<String> {
    Read::Unknown {
        what: "No native session-process observation accompanied this read".into(),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConversationView {
    pub id: Option<String>,
    pub state: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResumeCommand {
    pub ready: bool,
    pub mode: String,
    pub reason: Option<String>,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentRow {
    #[serde(default, skip_serializing_if = "se_types::ProviderSettings::is_empty")]
    pub provider_settings: se_types::ProviderSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_policy_notice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acp_runtime: Option<Read<super::AcpRuntimeView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_activity: Option<Read<ProviderActivityView>>,
    /// The Codex login this agent's shared app-server uses now; a login replaced
    /// while agents run is followed, so this names the current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_login: Option<Read<CodexLoginView>>,
    pub id: AgentId,
    pub name: String,
    pub role: Option<String>,
    pub provider: Provider,
    pub model: Option<String>,
    pub profile: String,
    pub session: SessionView,
    pub conversation: ConversationView,
    pub resume: ResumeCommand,
    pub unread: Option<u64>,
    pub last_activity_at: Option<String>,
    /// What the agent is doing, derived from observed facts; absent on rows
    /// no status read has settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AgentStateView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secode_binding: Option<Read<super::SecodeBindingView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secode_runtime: Option<Read<super::SecodeRuntimeView>>,
}
/// Which Codex login serves an agent. Identifiers only; never a credential.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CodexLoginView {
    /// The login's Codex home folder.
    pub home: String,
    /// The account the login is signed in to, when the login records one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}
/// An agent's state, derived from facts StateEngine observes, never from the
/// agent's own label.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentStateView {
    /// `working`, `attention`, `blocked`, `idle`, `running` (alive, turn not
    /// observed), `turn-unreadable`, `starting`, `stopping`, `stopped` or
    /// `unreachable`.
    pub state: String,
    /// When the state began, when StateEngine can say.
    pub since: Option<String>,
    pub elapsed_seconds: Option<u64>,
    /// The agent's latest question that has no reply yet.
    pub waiting_on: Option<WaitingOnView>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WaitingOnView {
    pub message_id: se_types::MessageId,
    pub to: String,
    pub asked_at: String,
}
/// A retained provider turn observation, not native liveness or task success.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProviderActivityView {
    pub activity: String,
    pub detail: String,
    pub quiet_seconds: Option<u64>,
    /// When this activity began, such as the start of an active turn, and how
    /// long ago that was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_seconds: Option<u64>,
    pub next_step: Option<String>,
}
/// Single-agent readback reuses the status/list row without flattening Read.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentStatusOutput {
    pub agent: Read<AgentRow>,
}
/// Stable cause codes shared by launch receipts and saved-session readback.
pub fn containment_cause_code(cause: &se_store::ContainmentCause) -> &'static str {
    match cause {
        se_store::ContainmentCause::NoUserManager => "no-user-manager",
        se_store::ContainmentCause::NoDelegation => "no-delegation",
        se_store::ContainmentCause::CgroupV2Absent => "cgroup-v2-absent",
        se_store::ContainmentCause::CgroupUnreadable => "cgroup-unreadable",
        se_store::ContainmentCause::ScopeCreateFailed => "scope-create-failed",
    }
}

/// Shared plain explanation of the stable containment code.
pub fn containment_cause_description(code: &str) -> &str {
    match code {
        "no-user-manager" => "No user service manager is available for containment.",
        "no-delegation" => {
            "This process backend has not established a delegated containment scope for this agent."
        }
        "cgroup-v2-absent" => "The OS does not provide cgroup v2 containment.",
        "cgroup-unreadable" => "The OS containment configuration cannot be read.",
        "scope-create-failed" => "The OS could not create the containment scope.",
        other => other,
    }
}
