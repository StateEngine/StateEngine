//! Closed inputs for owner administration and FULL writes. Authority and allocated
//! identities are supplied separately by the admitted caller.
use super::inputs::{Validate, bounded, name};
use crate::config_policy::Provider;
use schemars::JsonSchema;
use se_types::{AgentId, Cursor, IdempotencyKey, Result, SeError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCreate {
    /// Named declarative ACP harness, saved with this agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub name: String,
    pub provider: Option<Provider>,
    pub model: Option<String>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for AgentCreate {
    fn validate(&self) -> Result<()> {
        name("agent name", &self.name)?;
        if let Some(harness) = &self.harness {
            crate::config_policy::harness::validate_name(harness)?;
        }
        if let Some(model) = &self.model {
            bounded("model", model, 256, false)?;
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
