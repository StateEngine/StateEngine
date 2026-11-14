use super::{
    DirectoryEffect, FileEffect, IntegrationEffect, Named, ProcessView, ResumeCommand, Witness,
};
use schemars::JsonSchema;
use se_config::config_policy::{Provider, ResolvedProfile};
use se_types::{AgentId, IdempotencyKey, Read, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StopFact {
    pub target: String,
    pub complete: bool,
    pub witness: Witness,
    pub resume: ResumeCommand,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EndpointRecovery {
    pub original: se_types::NativePath,
    pub retained: se_types::NativePath,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeStart {
    pub state: String,
    pub process: ProcessView,
    pub generation: u64,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_recovery: Option<EndpointRecovery>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeStop {
    pub complete: bool,
    /// No stop was sent; native exclusion and retained custody proved absence.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub already_down: bool,
    pub stops: Vec<StopFact>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PathEffect {
    pub scope: String,
    pub before_entries: Vec<String>,
    pub after_entries: Vec<String>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RevocationEffect {
    pub session: SessionId,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UninstallOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_cleanup: Option<InitializedHomeCleanup>,
    pub idempotency_key: IdempotencyKey,
    pub complete: bool,
    pub install_files: Vec<FileEffect>,
    pub directories: Vec<DirectoryEffect>,
    pub integrations: Vec<IntegrationEffect>,
    pub stops: Vec<StopFact>,
    pub revocations: Vec<RevocationEffect>,
    pub path: PathEffect,
    pub preserved: Vec<String>,
    pub recovery: Vec<RecoveryDirectoryEffect>,
    /// Completion checks can fail after native effects; keep both facts visible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<se_types::ErrorBody>,
}
/// Native no-follow inventory of replacement recovery siblings. A filename
/// prefix alone never grants deletion or restoration authority.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryDirectoryEffect {
    pub directory: String,
    pub copies: Read<Vec<RecoveryCopy>>,
    /// Same finite held-parent scan: exact installer temps with native ownership
    /// and no-follow custody. Unknown/unreadable scans cannot complete uninstall.
    pub temporary_files: Read<Vec<FileEffect>>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryCopy {
    pub path: String,
    /// Set only after native identity/digest/security proof and outside readback
    /// restore this copy to an exact target in the original uninstall plan.
    pub restored_to: Option<String>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LaunchOutput {
    pub schema: String,
    pub agent: Named<AgentId>,
    pub process: ProcessView,
    pub session_id: SessionId,
    pub provider: Provider,
    pub model: Option<String>,
    pub permission_profile: ResolvedProfile,
    pub conversation_id: String,
}

/// Direct initialization grants authority only over named runtime artifacts,
/// while the store and identity remain available for adoption or resume.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitializedHomeCleanup {
    pub runtime: Read<RuntimeStop>,
    pub runtime_files: Vec<FileEffect>,
    pub manual_data_removal: String,
}
