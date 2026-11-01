//! Closed inputs for owner administration and FULL writes. Authority and allocated
//! identities are supplied separately by the admitted caller.
use super::inputs::{Validate, bounded, name};
use crate::config_policy::Provider;
use schemars::JsonSchema;
use se_types::{AgentId, DecisionId, IdempotencyKey, Result, SeError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCreate {
    pub name: String,
    pub provider: Option<Provider>,
    pub model: Option<String>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for AgentCreate {
    fn validate(&self) -> Result<()> {
        name("agent name", &self.name)?;
        if let Some(model) = &self.model {
            bounded("model", model, 256, false)?;
        }
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

fn revision(value: Option<u64>) -> Result<()> {
    if value.is_some_and(|value| value == 0 || value > i64::MAX as u64) {
        return Err(SeError::invalid(
            "expect",
            "a positive supported entity revision",
        ));
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionPropose {
    pub key: String,
    pub statement: String,
    pub rationale: Option<String>,
    pub supersedes: Option<DecisionId>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for DecisionPropose {
    fn validate(&self) -> Result<()> {
        bounded("decision key", &self.key, 128, false)?;
        if !self
            .key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            || !self.key.as_bytes()[0].is_ascii_alphanumeric()
        {
            return Err(SeError::invalid(
                "decision key",
                "a lower-case dotted key starting with a letter or digit",
            ));
        }
        bounded("statement", &self.statement, 8192, false)?;
        if let Some(reason) = &self.rationale {
            bounded("rationale", reason, 2048, false)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRatify {
    pub decision_id: DecisionId,
    pub expect: Option<u64>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for DecisionRatify {
    fn validate(&self) -> Result<()> {
        revision(self.expect)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionReject {
    pub decision_id: DecisionId,
    pub reason: String,
    pub expect: Option<u64>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for DecisionReject {
    fn validate(&self) -> Result<()> {
        revision(self.expect)?;
        bounded("reason", &self.reason, 2048, false)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRetract {
    pub decision_id: DecisionId,
    pub reason: String,
    pub expect: Option<u64>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for DecisionRetract {
    fn validate(&self) -> Result<()> {
        revision(self.expect)?;
        bounded("reason", &self.reason, 2048, false)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionSupersede {
    pub decision_id: DecisionId,
    pub replacement_id: DecisionId,
    pub expect: Option<u64>,
    pub replacement_expect: Option<u64>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for DecisionSupersede {
    fn validate(&self) -> Result<()> {
        revision(self.expect)?;
        revision(self.replacement_expect)?;
        if self.decision_id == self.replacement_id {
            return Err(SeError::invalid(
                "replacement",
                "a distinct replacement decision",
            ));
        }
        Ok(())
    }
}
