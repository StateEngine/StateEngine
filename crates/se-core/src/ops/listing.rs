//! Public owner agent listing over the same finite saved-identity reader as status.
use super::{AgentRow, inputs::Validate};
use crate::{commit::Cx, scope};
use schemars::JsonSchema;
use se_types::{Cursor, Page, PageRequest, Result, SeError};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU32, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentList {
    #[serde(default = "default_limit")]
    pub limit: u16,
    #[serde(default)]
    pub cursor: Option<Cursor>,
}
fn default_limit() -> u16 {
    20
}
impl Validate for AgentList {
    fn validate(&self) -> Result<()> {
        if !(1..=100).contains(&self.limit) {
            return Err(SeError::invalid("limit", "1..100 agents per page"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentPage {
    pub project: se_types::Named<se_types::ProjectId>,
    pub consistency: String,
    #[serde(flatten)]
    pub page: Page<AgentRow>,
}
pub fn agents<R: se_store::Snapshot>(input: AgentList, cx: &mut Cx<'_, R>) -> Result<AgentPage> {
    input.validate()?;
    scope::project(cx.admission)?;
    let budget = se_store::ReadBudget {
        page: PageRequest {
            after: input.cursor,
            limit: NonZeroU32::new(u32::from(input.limit))
                .ok_or_else(|| SeError::invalid("limit", "positive"))?,
            max_bytes: NonZeroU32::new(192 * 1024)
                .ok_or_else(|| SeError::invalid("agent bytes", "positive"))?,
        },
        deadline: Duration::from_secs(5),
    };
    let project = super::receipt::named_project(cx)?;
    Ok(AgentPage {
        project,
        consistency: "live-keyset".into(),
        page: super::agent_status::page(budget, cx)?,
    })
}
