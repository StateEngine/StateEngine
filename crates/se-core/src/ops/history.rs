//! Bounded public history and text search over the store's scoped, filter-bound
//! immutable event reader. Exact reads and pages share one public payload projector.
use super::{HistoryEvent, inputs::Validate};
use crate::{commit::Cx, scope, store_error::store_error};
use schemars::JsonSchema;
use se_store::{
    HistoryDirection, HistoryQuery, PositionPurpose, ReadBudget, SearchQuery, Snapshot, StoredText,
};
use se_types::{AgentId, Cursor, EventId, Page, PageRequest, Result, SeError, SessionId};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU32, time::Duration};

const DEFAULT_SEARCH_BUDGET: u32 = 192 * 1024;
const MIN_SEARCH_BUDGET: u32 = 1024;
const MAX_SEARCH_BUDGET: u32 = 1_048_576;

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
    /// Read the page newest-first; the cursor continues toward the oldest event.
    #[serde(default)]
    pub newest: bool,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<AgentId>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistorySearch {
    /// Text to match case-insensitively across authorized history records (1..512 characters).
    pub query: String,
    #[serde(default)]
    pub session: Option<SessionId>,
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub since: Option<Cursor>,
    /// Maximum candidate events scanned in this page (1..100).
    #[serde(default = "default_limit")]
    pub limit: u16,
    /// Maximum UTF-8 bytes scanned in this page (1024..1048576).
    #[serde(default = "default_search_budget")]
    pub byte_budget: u32,
    #[serde(default)]
    pub cursor: Option<Cursor>,
    /// Scan newest-first; the cursor continues toward older events.
    #[serde(default)]
    pub newest: bool,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<AgentId>,
}
fn default_limit() -> u16 {
    20
}
fn default_search_budget() -> u32 {
    DEFAULT_SEARCH_BUDGET
}
pub(crate) fn position_cursor(value: String) -> Result<Cursor> {
    if looks_like_time(&value) {
        return Err(SeError::invalid(
            "--position",
            "an opaque history position cursor, the position value from se history --event; this command has no time-based flag",
        ));
    }
    Cursor::new(value)
}
fn looks_like_time(value: &str) -> bool {
    if value.bytes().any(|byte| byte == b':') {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() >= 10
        && bytes[0..4].iter().all(|b| b.is_ascii_digit())
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(|b| b.is_ascii_digit())
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(|b| b.is_ascii_digit())
}
impl Validate for HistoryList {
    fn validate(&self) -> Result<()> {
        validate_page(self.limit, &self.kinds)
    }
}
impl Validate for HistorySearch {
    fn validate(&self) -> Result<()> {
        if self.query.is_empty() || self.query.chars().count() > 512 || self.query.contains('\0') {
            return Err(SeError::invalid(
                "query",
                "1..512 UTF-8 characters without NUL",
            ));
        }
        if !(MIN_SEARCH_BUDGET..=MAX_SEARCH_BUDGET).contains(&self.byte_budget) {
            return Err(SeError::invalid("byte_budget", "1024..1048576 UTF-8 bytes"));
        }
        validate_page(self.limit, &self.kinds)
    }
}
fn validate_page(limit: u16, kinds: &[String]) -> Result<()> {
    if !(1..=100).contains(&limit) || kinds.len() > 52 {
        return Err(SeError::invalid(
            "history page",
            "1..100 items and at most 52 exact kinds",
        ));
    }
    for name in kinds {
        kind(name)?;
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HistoryPage {
    pub consistency: String,
    pub read_at: Cursor,
    #[serde(flatten)]
    pub page: Page<HistoryEvent>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SearchHit {
    pub event_id: EventId,
    pub revision: u64,
    pub snippet: String,
    pub body_complete: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SearchPage {
    pub consistency: String,
    pub read_at: Cursor,
    /// Count of intentionally erased candidates omitted from this page.
    pub erased: u64,
    #[serde(flatten)]
    pub page: Page<SearchHit>,
}
struct HistoryFilter {
    owner_agent: Option<AgentId>,
    session: Option<SessionId>,
    kinds: Vec<String>,
    since: Option<Cursor>,
    newest: bool,
}
fn build_query<R: Snapshot>(
    filter: HistoryFilter,
    op_name: &str,
    cx: &mut Cx<'_, R>,
) -> Result<HistoryQuery> {
    scope::project(cx.admission)?;
    if let Some(agent) = &filter.owner_agent {
        scope::working_agent(cx.admission, Some(agent), op_name)?;
    }
    Ok(HistoryQuery {
        agent: filter.owner_agent,
        session: filter.session,
        // The public timeline is defined by its explicit payload catalogue.
        // Native process/credential internals never become accidental default
        // rows that cannot be rendered or safely exported.
        kinds: if filter.kinds.is_empty() {
            PUBLIC_KINDS.iter().map(|(_, kind)| *kind).collect()
        } else {
            filter
                .kinds
                .iter()
                .map(|name| kind(name))
                .collect::<Result<_>>()?
        },
        families: Vec::new(),
        transcript: match (
            filter.kinds.iter().any(|k| k == "session.turn"),
            filter.kinds.iter().any(|k| k == "transcript.event"),
        ) {
            _ if filter.kinds.is_empty() => se_store::TranscriptFilter::All,
            (true, false) => se_store::TranscriptFilter::Chat,
            (false, true) => se_store::TranscriptFilter::Metadata,
            _ => se_store::TranscriptFilter::All,
        },
        since: filter
            .since
            .as_ref()
            .map(|cursor| cx.read.cursor_position(cursor, PositionPurpose::History))
            .transpose()
            .map_err(|error| store_error(&error))?,
        direction: if filter.newest {
            HistoryDirection::NewestFirst
        } else {
            HistoryDirection::OldestFirst
        },
    })
}
pub fn list<R: Snapshot>(input: HistoryList, cx: &mut Cx<'_, R>) -> Result<HistoryPage> {
    input.validate()?;
    let query = build_query(
        HistoryFilter {
            owner_agent: input.owner_agent,
            session: input.session,
            kinds: input.kinds,
            since: input.since,
            newest: input.newest,
        },
        "history.list",
        cx,
    )?;
    let page = cx
        .read
        .history(
            query,
            ReadBudget {
                page: PageRequest {
                    after: input.cursor,
                    limit: NonZeroU32::new(u32::from(input.limit))
                        .ok_or_else(|| SeError::invalid("history limit", "positive"))?,
                    max_bytes: NonZeroU32::new(DEFAULT_SEARCH_BUDGET)
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
pub fn search<R: Snapshot>(input: HistorySearch, cx: &mut Cx<'_, R>) -> Result<SearchPage> {
    input.validate()?;
    let history = build_query(
        HistoryFilter {
            owner_agent: input.owner_agent,
            session: input.session,
            kinds: input.kinds,
            since: input.since,
            newest: input.newest,
        },
        "history.search",
        cx,
    )?;
    let result = cx
        .read
        .search(
            SearchQuery {
                text: input.query,
                history,
            },
            ReadBudget {
                page: PageRequest {
                    after: input.cursor,
                    limit: NonZeroU32::new(u32::from(input.limit))
                        .ok_or_else(|| SeError::invalid("search limit", "positive"))?,
                    max_bytes: NonZeroU32::new(input.byte_budget)
                        .ok_or_else(|| SeError::invalid("search byte_budget", "positive"))?,
                },
                deadline: Duration::from_secs(5),
            },
        )
        .map_err(|error| store_error(&error))?;
    let read_at = result
        .page
        .window()
        .fields()
        .and_then(|fields| fields.end_cursor.clone())
        .ok_or_else(|| {
            scope::unreadable(
                "search checkpoint",
                "store supplied no opaque checked page position",
            )
        })?;
    let window = result.page.window().clone();
    let next = result.page.next().cloned();
    let erased = result.erased;
    let mut items = Vec::with_capacity(result.page.items().len());
    for hit in result.page.into_items() {
        let StoredText::Present(snippet) = hit.snippet else {
            return Err(scope::unreadable(
                "search hit snippet",
                "store returned a search hit without present snippet text",
            ));
        };
        items.push(SearchHit {
            event_id: hit.event,
            revision: hit.revision.value.get(),
            snippet,
            body_complete: hit.body_complete,
        });
    }
    Ok(SearchPage {
        consistency: "live-keyset".into(),
        read_at,
        erased,
        page: Page::new(items, window, next)?,
    })
}
const PUBLIC_KINDS: &[(&str, se_store::EventKind)] = &[
    ("assignment.opened", se_store::EventKind::AssignmentOpened),
    (
        "assignment.transitioned",
        se_store::EventKind::AssignmentTransitioned,
    ),
    (
        "project.captain_changed",
        se_store::EventKind::ProjectCaptainChanged,
    ),
    ("legacy.retained", se_store::EventKind::LegacyRetained),
    ("alias.imported", se_store::EventKind::AliasImported),
    ("message.superseded", se_store::EventKind::MessageSuperseded),
    ("session.turn", se_store::EventKind::SessionTurn),
    ("transcript.event", se_store::EventKind::SessionTurn),
    ("capture.verified", se_store::EventKind::CaptureVerified),
    ("capture.suppressed", se_store::EventKind::CaptureSuppressed),
    ("message.sent", se_store::EventKind::MessageSent),
    ("message.work_sent", se_store::EventKind::WorkMessageSent),
    ("message.read", se_store::EventKind::MessageRead),
    ("message.dismissed", se_store::EventKind::MessageDismissed),
    ("message.delivered", se_store::EventKind::MessageDelivered),
    ("working_state.set", se_store::EventKind::WorkingStateSet),
    (
        "principal.registered",
        se_store::EventKind::PrincipalRegistered,
    ),
    ("principal.renamed", se_store::EventKind::PrincipalRenamed),
    ("profile.saved", se_store::EventKind::ProfileSaved),
    ("grant.recorded", se_store::EventKind::GrantRecorded),
    ("decision.proposed", se_store::EventKind::DecisionProposed),
    ("decision.ratified", se_store::EventKind::DecisionRatified),
    ("decision.rejected", se_store::EventKind::DecisionRejected),
    ("decision.retracted", se_store::EventKind::DecisionRetracted),
    (
        "decision.superseded",
        se_store::EventKind::DecisionSuperseded,
    ),
];
const IMPORT_KINDS: &[(&str, se_store::EventKind)] = &[
    ("import.started", se_store::EventKind::ImportStarted),
    ("import.progress", se_store::EventKind::ImportProgress),
    ("import.finished", se_store::EventKind::ImportFinished),
    ("import.unreadable", se_store::EventKind::ImportUnreadable),
];
fn kind(name: &str) -> Result<se_store::EventKind> {
    PUBLIC_KINDS
        .iter()
        .chain(IMPORT_KINDS.iter())
        .find_map(|(wire, kind)| (*wire == name).then_some(*kind))
        .ok_or_else(|| {
            SeError::invalid(
                "kind",
                "an exact public event kind; use session.turn for captured conversation history",
            )
        })
}
