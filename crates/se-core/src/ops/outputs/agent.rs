use super::ProcessView;
use crate::config_policy::Provider;
use schemars::JsonSchema;
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
}
/// Single-agent readback reuses the status/list row without flattening Read.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentStatusOutput {
    pub agent: Read<AgentRow>,
}
impl AgentStatusOutput {
    pub fn into_envelope(self) -> super::super::Envelope<Self> {
        super::super::Envelope::new(
            crate::registry::Family {
                name: "se.agent-status",
                major: 1,
            },
            self,
        )
    }
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
        "no-delegation" => "The OS has not delegated a containment scope to this user.",
        "cgroup-v2-absent" => "The OS does not provide cgroup v2 containment.",
        "cgroup-unreadable" => "The OS containment configuration cannot be read.",
        "scope-create-failed" => "The OS could not create the containment scope.",
        other => other,
    }
}
