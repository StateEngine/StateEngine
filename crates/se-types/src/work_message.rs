//! Explicit recipients and purpose for a shared work message. This describes
//! delivery; it never grants the sender authority to assign or ratify work.
use crate::{AgentId, Result, SeError};

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkAction {
    Admit,
    Assign,
    Return,
    Question,
    RulingRequest,
    Ruling,
    Finding,
    Notify,
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct WorkAddressing {
    pub action: WorkAction,
    pub addressees: Vec<AgentId>,
}

impl WorkAddressing {
    pub fn validate(&self) -> Result<()> {
        if !(1..=20).contains(&self.addressees.len()) {
            return Err(SeError::invalid(
                "work.addressees",
                "1..20 distinct canonical agent IDs",
            ));
        }
        for (index, agent) in self.addressees.iter().enumerate() {
            if self.addressees[..index].contains(agent) {
                return Err(SeError::invalid(
                    "work.addressees",
                    "distinct canonical agent IDs",
                ));
            }
        }
        Ok(())
    }
}
