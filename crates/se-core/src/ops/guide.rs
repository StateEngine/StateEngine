//! Installed workflow guidance DTOs shared by CLI and MCP, without state access.
use super::{Validate, inputs::bounded};
use schemars::JsonSchema;
use se_types::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetaGuide {
    /// Exact topic name from the index; omit to list names and summaries only.
    pub topic: Option<String>,
}

impl Validate for MetaGuide {
    fn validate(&self) -> Result<()> {
        if let Some(topic) = &self.topic {
            bounded("guide topic", topic, 64, false)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GuideTopicSummary {
    pub name: String,
    pub title: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuideOutput {
    Index {
        topics: Vec<GuideTopicSummary>,
    },
    Topic {
        name: String,
        title: String,
        body: String,
    },
}
