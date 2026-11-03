//! A bounded live decision-head page, shared by the CLI and MCP readers.
use super::{
    DecisionRow,
    inputs::{Validate, bounded},
};
use crate::{commit::Cx, scope, store_error::store_error};
use schemars::JsonSchema;
use se_store::{DecisionQuery, EventBody, ReadBudget, Snapshot};
use se_types::{Cursor, DecisionId, Named, Page, PageRequest, ProjectId, Result, SeError};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU32, time::Duration};
mod types;
pub use types::{DecisionPageRow, DecisionUnreadable, UnreadableDecisionFields};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionList {
    #[schemars(length(min = 1, max = 512))]
    pub id: Option<String>,
    #[serde(default)]
    pub pending: bool,
    #[serde(default)]
    pub history: bool,
    #[serde(default = "default_limit")]
    #[schemars(range(min = 1, max = 100))]
    pub limit: u16,
    pub cursor: Option<Cursor>,
}
fn default_limit() -> u16 {
    20
}
impl Validate for DecisionList {
    fn validate(&self) -> Result<()> {
        if !(1..=100).contains(&self.limit) {
            return Err(SeError::invalid("limit", "1..100 decisions per page"));
        }
        if let Some(id) = &self.id {
            bounded("id", id, 512, false)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionFilter {
    pub id: Option<DecisionId>,
    pub pending: bool,
    pub history: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionPage {
    pub project: Named<ProjectId>,
    pub filter: DecisionFilter,
    pub consistency: String,
    #[serde(flatten)]
    pub page: Page<DecisionPageRow>,
}
fn preview(row: &mut DecisionRow, project: &ProjectId) {
    if let Some((boundary, _)) = row.statement.text.char_indices().nth(400) {
        row.statement.text.truncate(boundary);
        row.statement.complete = false;
        row.statement.command = Some(format!("se decision show {} --project {project}", row.id));
        row.statement.argv = Some(vec![
            "se".into(),
            "decision".into(),
            "show".into(),
            row.id.to_string(),
            "--project".into(),
            project.to_string(),
        ]);
    }
}
pub fn read<R: Snapshot>(input: DecisionList, cx: &mut Cx<'_, R>) -> Result<DecisionPage> {
    input.validate()?;
    scope::project(cx.admission)?;
    let project = super::receipt::named_project(cx)?;
    let id = if let Some(id) = input.id {
        let registry = cx
            .read
            .legacy_registry()
            .map_err(|error| store_error(&error))?;
        Some(
            DecisionId::from_legacy(id.clone())
                .or_else(|_| DecisionId::from_registered_legacy(id, &registry))?,
        )
    } else {
        None
    };
    let filter = DecisionFilter {
        id: id.clone(),
        pending: input.pending,
        history: input.history,
    };
    let page = cx
        .read
        .decision_rows(
            DecisionQuery {
                id,
                pending_only: input.pending,
                history: input.history,
            },
            ReadBudget {
                page: PageRequest {
                    after: input.cursor,
                    limit: NonZeroU32::new(u32::from(input.limit))
                        .ok_or_else(|| SeError::invalid("limit", "positive"))?,
                    max_bytes: NonZeroU32::new(192 * 1024)
                        .ok_or_else(|| SeError::invalid("decision bytes", "positive"))?,
                },
                deadline: Duration::from_secs(5),
            },
        )
        .map_err(|error| store_error(&error))?;
    let mut fields = page
        .window()
        .fields()
        .cloned()
        .ok_or_else(|| scope::unreadable("decision page", "store accounting is unavailable"))?;
    let next = page.next().cloned();
    let mut rows = Vec::with_capacity(page.items().len());
    for head in page.into_items() {
        let result = match head {
            se_types::Read::Present { value: head } => {
                let original = head.original.as_deref().unwrap_or(&head.current);
                match &original.body {
                    EventBody::DecisionProposed { decision, .. } => {
                        super::decision::row(decision, &head.current, cx)
                    }
                    _ => Err(scope::unreadable(
                        "decision page",
                        "original proposal is unavailable",
                    )),
                }
            }
            other => scope::require_present(
                other,
                "decision head",
                "Restore the stored decision content before retrying this read.",
            )
            .map(|_| unreachable!()),
        };
        match result {
            Ok(mut row) => {
                preview(&mut row, &project.id);
                rows.push(DecisionPageRow::Present {
                    row: Box::new(row),
                    unreadable: None,
                });
            }
            Err(error) if error.class() == se_types::Class::Unreadable => {
                fields.unreadable += 1;
                rows.push(DecisionPageRow::Unreadable {
                    row: Box::default(),
                    unreadable: DecisionUnreadable {
                        reason: error.body.message(),
                    },
                });
            }
            Err(error) => return Err(error),
        }
    }
    fields.bytes = serde_json::to_vec(&rows)
        .map_err(|_| SeError::invalid("decision page", "encodable rows"))?
        .len() as u64;
    if fields.bytes > u64::from(fields.max_bytes.get()) {
        return Err(SeError::too_large(
            "decision page; repeat with a smaller --limit",
            fields.max_bytes.get() as usize,
            fields.bytes as usize,
        ));
    }
    Ok(DecisionPage {
        project,
        filter,
        consistency: "live-keyset".into(),
        page: Page::new(rows, se_types::Window::new(fields)?, next)?,
    })
}
