//! Closed inputs for owner administration and FULL writes. Authority and allocated
//! identities are supplied separately by the admitted caller.
use super::inputs::{Validate, bounded, name};
use schemars::JsonSchema;
use se_config::config_policy::Provider;
use se_types::{AgentId, Cursor, IdempotencyKey, Result, SeError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCreate {
    #[serde(default, skip_serializing_if = "provider_settings_empty")]
    pub provider_settings: Box<se_types::ProviderSettings>,
    /// Native provider choice or named declarative ACP harness, saved with this agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub name: String,
    pub provider: Option<Provider>,
    pub model: Option<String>,
    /// Optional named permission profile; validated against `[delegation].allow` for agent callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub idempotency_key: IdempotencyKey,
}
fn provider_settings_empty(settings: &se_types::ProviderSettings) -> bool {
    settings.is_empty()
}
impl Validate for AgentCreate {
    fn validate(&self) -> Result<()> {
        name("agent name", &self.name)?;
        if let Some(harness) = &self.harness {
            se_config::config_policy::harness::validate_name(harness)?;
        }
        if let Some(model) = &self.model {
            bounded("model", model, 256, false)?;
        }
        if let Some(profile) = &self.profile {
            bounded("profile", profile, 64, false)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentRename {
    pub agent: String,
    pub name: String,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for AgentRename {
    fn validate(&self) -> Result<()> {
        bounded("agent selector", &self.agent, 128, false)?;
        name("agent name", &self.name)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentShow {
    pub target_agent_id: Option<AgentId>,
}
impl Validate for AgentShow {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigGet {
    pub key: String,
    #[serde(default)]
    pub origin: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigSet {
    pub key: String,
    pub value: String,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigList {
    #[serde(default)]
    pub origin: bool,
    #[serde(default = "default_config_list_limit")]
    pub limit: u16,
    #[serde(default)]
    pub cursor: Option<Cursor>,
}
fn default_config_list_limit() -> u16 {
    100
}
impl Validate for ConfigGet {
    fn validate(&self) -> Result<()> {
        bounded("configuration key", &self.key, 1024, false)
    }
}
impl Validate for ConfigSet {
    fn validate(&self) -> Result<()> {
        bounded("configuration key", &self.key, 1024, false)?;
        bounded("configuration value", &self.value, 4096, true)
    }
}
impl Validate for ConfigList {
    fn validate(&self) -> Result<()> {
        if !(1..=500).contains(&self.limit) {
            return Err(SeError::invalid(
                "limit",
                "1..500 configuration rows per page",
            ));
        }
        Ok(())
    }
}
/// Owner registration of a protocol harness descriptor in the state home's
/// `config.toml`. The owner CLI route edits the file; the kernel never plans it.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HarnessAdd {
    /// New `[harnesses.NAME]` entry; built-in provider names are refused.
    pub name: String,
    /// Native executable that speaks ACP version 1 over standard input and output.
    pub command: String,
    /// Arguments passed to the executable without a shell.
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Environment variable names the harness may read from the owner's environment.
    #[serde(default)]
    pub environment: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HarnessAddOutput {
    pub name: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
    /// Launch profile the new descriptor maps, from `[providers.acp].profile`.
    pub profile: String,
    /// The configuration file that now holds the descriptor.
    pub configuration: String,
}

impl Validate for HarnessAdd {
    fn validate(&self) -> Result<()> {
        se_config::config_policy::harness::validate_name(&self.name)?;
        if se_types::Provider::from_id(&self.name).is_some() {
            return Err(SeError::invalid(
                "harness name",
                "a name other than a built-in provider; built-in providers need no descriptor",
            ));
        }
        bounded("harness command", &self.command, 4096, false)?;
        if self.arguments.len() > 128 || self.environment.len() > 128 {
            return Err(SeError::invalid(
                "harness descriptor",
                "at most 128 arguments and 128 environment variable names",
            ));
        }
        Ok(())
    }
}
