//! Executable-owned ACP invocation settings; no harness-specific dispatch.
use super::invalid;
use schemars::JsonSchema;
use se_types::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AcpConfig {
    /// Default descriptor for newly created ACP agents; existing agents keep their saved choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// Native argv, without a shell. `{model}` expands the selected saved model.
    pub arguments: Vec<String>,
    /// Additional owner environment names explicitly selected for the protocol agent.
    pub environment: Vec<String>,
    /// Optional mode the agent must echo. Empty uses its announced default.
    pub mode: String,
    /// Accepts HTTP MCP from agents that use it without advertising the capability.
    pub unadvertised_http_mcp: bool,
}
impl AcpConfig {
    pub fn is_default(&self) -> bool {
        self.harness.is_none()
            && self.arguments.is_empty()
            && self.environment.is_empty()
            && self.mode.is_empty()
            && !self.unadvertised_http_mcp
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.arguments.len() > 128
            || self
                .arguments
                .iter()
                .any(|v| v.len() > 64 * 1024 || v.contains('\0'))
            || self.arguments.iter().map(String::len).sum::<usize>() > 1024 * 1024
        {
            return Err(invalid(
                "acp.arguments",
                "expected at most 128 native arguments and one MiB without NUL",
            ));
        }
        if self.environment.len() > 128
            || self.environment.iter().any(|v| !valid_environment_name(v))
        {
            return Err(invalid(
                "acp.environment",
                "expected at most 128 explicit environment variable names",
            ));
        }
        if let Some(name) = self
            .environment
            .iter()
            .find(|name| reserved_environment_name(name))
        {
            return Err(invalid(
                "acp.environment",
                &format!(
                    "{name} is reserved for runtime session or machine authority; remove it and select the provider's own environment variable names instead"
                ),
            ));
        }
        if self.mode.len() > 512 || self.mode.chars().any(char::is_control) {
            return Err(invalid(
                "acp.mode",
                "omit it or select a bounded protocol mode",
            ));
        }
        Ok(())
    }
}

/// A variable name an agent may be given: letters, digits and underscores,
/// 1 to 128 bytes.
pub fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Names that carry StateEngine's own session or machine authority and are
/// never passed to an agent.
pub fn reserved_environment_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name == "SE_SESSION" || name.starts_with("STATEENGINE_") || name.starts_with("SECODE_")
}
