//! Bounded public history over the store's scoped, filter-bound immutable event
//! reader. Exact reads and pages share one public payload projector.
use super::{HistoryEvent, inputs::Validate};
use crate::{commit::Cx, scope, store_error::store_error};
use schemars::JsonSchema;
use se_store::{HistoryQuery, PositionPurpose, ReadBudget, Snapshot};
use se_types::{AgentId, Cursor, Page, PageRequest, Result, SeError, SessionId};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU32, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryList {
    #[serde(default)]
    pub session: Option<SessionId>,
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub since: Option<Cursor>,
    #[serde(default = "default_limit")]
    pub limit: u16,
    #[serde(default)]
    pub cursor: Option<Cursor>,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<AgentId>,
}
fn default_limit() -> u16 {
    20
}
impl Validate for HistoryList {
    fn validate(&self) -> Result<()> {
        if !(1..=100).contains(&self.limit) || self.kinds.len() > 52 {
            return Err(SeError::invalid(
                "history page",
                "1..100 items and at most 52 exact kinds",
            ));
        }
        for name in &self.kinds {
            kind(name)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HistoryPage {
    pub consistency: String,
    pub read_at: Cursor,
    #[serde(flatten)]
    pub page: Page<HistoryEvent>,
}
pub fn list<R: Snapshot>(input: HistoryList, cx: &mut Cx<'_, R>) -> Result<HistoryPage> {
    input.validate()?;
    scope::project(cx.admission)?;
    if let Some(agent) = &input.owner_agent {
        scope::working_agent(cx.admission, Some(agent), "history.list")?;
    }
    let query = HistoryQuery {
        agent: input.owner_agent,
        session: input.session,
        kinds: input
            .kinds
            .iter()
            .map(|name| kind(name))
            .collect::<Result<_>>()?,
        families: Vec::new(),
        since: input
            .since
            .as_ref()
            .map(|cursor| cx.read.cursor_position(cursor, PositionPurpose::History))
            .transpose()
            .map_err(|error| store_error(&error))?,
    };
    let page = cx
        .read
        .history(
            query,
            ReadBudget {
                page: PageRequest {
                    after: input.cursor,
                    limit: NonZeroU32::new(u32::from(input.limit))
                        .ok_or_else(|| SeError::invalid("history limit", "positive"))?,
                    max_bytes: NonZeroU32::new(192 * 1024)
                        .ok_or_else(|| SeError::invalid("history bytes", "positive"))?,
                },
                deadline: Duration::from_secs(5),
            },
        )
        .map_err(|error| store_error(&error))?;
    let mut fields =
        page.window().fields().cloned().ok_or_else(|| {
            scope::unreadable("history window", "store accounting is unavailable")
        })?;
    let read_at = fields.end_cursor.clone().ok_or_else(|| {
        scope::unreadable(
            "history checkpoint",
            "store supplied no opaque checked page position",
        )
    })?;
    let next = page.next().cloned();
    let mut items = Vec::with_capacity(page.items().len());
    for record in page.into_items() {
        items.push(super::event::project_event(record, cx)?);
    }
    fields.bytes = serde_json::to_vec(&items)
        .map_err(|_| SeError::invalid("history page", "encodable complete events"))?
        .len() as u64;
    if fields.bytes > u64::from(fields.max_bytes.get()) {
        return Err(SeError::too_large(
            "history page; repeat with a smaller --limit",
            fields.max_bytes.get() as usize,
            fields.bytes as usize,
        ));
    }
    Ok(HistoryPage {
        consistency: "live-keyset".into(),
        read_at,
        page: Page::new(items, se_types::Window::new(fields)?, next)?,
    })
}
fn kind(name: &str) -> Result<se_store::EventKind> {
    use se_store::EventKind::*;
    Ok(match name {
        "session.turn" => SessionTurn,
        "capture.suppressed" => CaptureSuppressed,
        "message.sent" => MessageSent,
        "working_state.set" => WorkingStateSet,
        "principal.registered" => PrincipalRegistered,
        "principal.renamed" => PrincipalRenamed,
        "profile.saved" => ProfileSaved,
        "grant.recorded" => GrantRecorded,
        "decision.proposed" => DecisionProposed,
        "decision.ratified" => DecisionRatified,
        "decision.rejected" => DecisionRejected,
        "decision.retracted" => DecisionRetracted,
        "decision.superseded" => DecisionSuperseded,
        _ => {
            return Err(SeError::invalid(
                "kind",
                "an exact public event kind; use session.turn for captured conversation history",
            ));
        }
    })
}
