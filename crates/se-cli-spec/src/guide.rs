//! Installed workflow guidance shared by CLI and MCP, without state access.
use se_core::ops::{GuideOutput, GuideTopicSummary, MetaGuide, Validate};
use se_types::{Result, SeError};

mod topics;

pub fn read(input: &MetaGuide) -> Result<GuideOutput> {
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
