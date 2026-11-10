//! Installed workflow guidance shared by CLI and MCP, without state access.
use super::{Validate, inputs::bounded};
use schemars::JsonSchema;
use se_types::{Result, SeError};
use serde::{Deserialize, Serialize};

mod topics;

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

pub(super) fn read(input: &MetaGuide) -> Result<GuideOutput> {
    input.validate()?;
    let Some(name) = &input.topic else {
        return Ok(GuideOutput::Index {
            topics: topics::TOPICS
                .iter()
                .map(|topic| GuideTopicSummary {
                    name: topic.name.into(),
                    title: topic.title.into(),
                    summary: topic.summary.into(),
                })
                .collect(),
        });
    };
    let topic = topics::TOPICS
        .iter()
        .find(|topic| topic.name == name)
        .ok_or_else(|| {
            SeError::invalid(
                "guide topic",
                &format!(
                    "an exact topic name from se guide (MCP: stateengine_help with no topic): {}",
                    topics::TOPICS
                        .iter()
                        .map(|topic| topic.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })?;
    Ok(GuideOutput::Topic {
        name: topic.name.into(),
        title: topic.title.into(),
        body: topic.body.into(),
    })
}
