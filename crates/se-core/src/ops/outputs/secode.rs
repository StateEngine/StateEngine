use schemars::JsonSchema;
use se_types::{NativePath, ProcessInstance, Read};
use serde::{Deserialize, Serialize};

/// Retained custody coordinates, separate from current native liveness and
/// authenticated execution observations. No service or session secret is exposed.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecodeBindingView {
    pub schema: String,
    pub service_profile: NativePath,
    pub service_process: ProcessInstance,
    pub client_process: ProcessInstance,
    pub session_id: String,
    pub initial_input_id: String,
    pub incarnation: String,
    pub service_instance: String,
    pub generation: u64,
    pub registration_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecodeRuntimeView {
    pub service_state: String,
    pub active: bool,
    pub execution_id: Read<String>,
    pub model: String,
    pub permission_preset: String,
    pub pending_permissions: u64,
    pub initial_input: Read<String>,
    pub output_stream: Read<String>,
}
