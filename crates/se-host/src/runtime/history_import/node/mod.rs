//! Pure Node user-history decoding. Original source custody and immutable
//! ranges are supplied by the host; no filesystem, environment or Node runtime.
use se_store::import::{ImportSnapshot, LegacyTarget};
mod human_name;
pub(super) use human_name::suffix as historical_human_name;
mod ledger;
mod message;
pub(super) mod profile;
mod registration;
mod time;
mod turns;
mod working;
use se_store::*;
use se_types::{AgentId, DecisionId, EventId, HumanId, MessageId, Read, SessionId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub enum NodeKind {
    Projects,
    Owners,
    Profiles,
    Ledger,
    Messages,
    WorkingState,
    Turns,
}
#[derive(Clone)]
pub struct NodeContext {
    pub admission: Admission,
    pub store: StoreInfo,
    pub source: SourceEvidence,
    pub import: RecordId,
    /// Trusted import observation, used only for undated configuration adoption.
    pub observed_at_us: i64,
    /// Safe profiles observed from the active current owner's configuration;
    /// source bytes cannot add a named bypass or an executable launch recipe.
    pub owner_profiles: Read<Vec<Profile>>,
    /// Earlier source operations still await dependencies; profile entries
    /// cannot yet be classified as outside this project.
    pub prerequisites_pending: bool,
    pub human_mappings: std::sync::Arc<std::collections::BTreeMap<HumanId, HumanId>>,
    pub human_names: super::human_plan::Names,
}
pub struct DecodedRow {
    pub events: Vec<NewEvent>,
    pub family: ImportFamily,
    pub legacy_id: String,
    pub target: LegacyTarget,
    /// Only selected user fields, and only where no typed owning text exists.
    pub retained: Option<Value>,
    pub resume: Vec<ResumeFact>,
    pub duplicate: bool,
    pub dropped_by_policy: bool,
    /// Profile documents report one disposition per contained user entry.
    pub dispositions: Option<ImportCounts>,
}
pub struct ResumeFact {
    pub session: SessionId,
    pub agent: AgentId,
    pub provider: Provider,
    pub native_reference: Option<String>,
    pub unsupported: bool,
}
pub fn record_id(domain: &str, key: &str) -> StoreResult<RecordId> {
    let digest = Sha256::digest(format!("stateengine.node-import/v1:{domain}:{key}"));
    RecordId::from_parts(0, digest[..10].try_into().map_err(invalid)?)
}
pub fn event_id(scope: &Scope, key: &str) -> StoreResult<EventId> {
    let key = serde_json::to_string(&(scope, key)).map_err(invalid)?;
    let digest = Sha256::digest(format!("stateengine.node-event/v1:{key}"));
    EventId::from_parts(0, digest[..10].try_into().map_err(invalid)?).map_err(invalid)
}
fn str_at<'a>(v: &'a Value, name: &str) -> StoreResult<&'a str> {
    v.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid(format!("Node row is missing {name}")))
}
fn text_at<'a>(v: &'a Value, name: &str) -> StoreResult<&'a str> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("Node row is missing text field {name}")))
}
fn optional(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(Value::as_str).map(str::to_owned)
}
fn agent<R: Snapshot>(read: &R, id: &str) -> StoreResult<AgentId> {
    AgentId::from_legacy(id)
        .or_else(|_| {
            AgentId::from_registered_legacy(
                id,
                &read
                    .legacy_registry()
                    .map_err(|e| se_types::SeError::invalid("import legacy registry", &e.cause))?,
            )
        })
        .map_err(|_| {
            fail(
                StoreErrorCode::ReferenceMissing,
                "agent reference has no exact imported source registration yet",
            )
        })
}
struct DeclaredAgent<'a>(&'a str);
impl se_types::LegacyIdRegistry for DeclaredAgent<'_> {
    fn contains(&self, kind: se_types::IdKind, text: &str) -> se_types::Result<bool> {
        Ok(kind == se_types::IdKind::AgentId && text == self.0)
    }
}
fn declared_agent(id: &str) -> StoreResult<AgentId> {
    AgentId::from_legacy(id)
        .or_else(|_| AgentId::from_registered_legacy(id, &DeclaredAgent(id)))
        .map_err(invalid)
}
fn mapped_human(cx: &NodeContext, source: HumanId) -> HumanId {
    cx.human_mappings.get(&source).cloned().unwrap_or(source)
}
fn actor<R: Snapshot>(cx: &NodeContext, read: &R, v: &Value) -> StoreResult<Actor> {
    let id = str_at(v, "actor_id")?;
    match str_at(v, "actor_type")? {
        "human" => Ok(Actor::Human(mapped_human(
            cx,
            HumanId::from_legacy(id).map_err(invalid)?,
        ))),
        "agent" => Ok(Actor::Agent(agent(read, id)?)),
        _ => Err(invalid("Node actor has an unsupported recorded kind")),
    }
}
fn seat<R: Snapshot>(cx: &NodeContext, read: &R, id: &str) -> StoreResult<Actor> {
    if id.starts_with("hum-") || id.starts_with("hu_") {
        Ok(Actor::Human(mapped_human(
            cx,
            HumanId::from_legacy(id).map_err(invalid)?,
        )))
    } else {
        Ok(Actor::Agent(agent(read, id)?))
    }
}
fn expected(read: Read<ProjectionRecord>) -> StoreResult<Expected> {
    match read {
        Read::Present { value } => Ok(Expected::Revision(value.revision)),
        Read::Absent { .. } => Ok(Expected::Absent),
        Read::Unreadable { reason, .. } => Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => Err(fail(StoreErrorCode::Unreadable, what)),
    }
}
fn require<T>(read: Read<T>) -> StoreResult<T> {
    match read {
        Read::Present { value } => Ok(value),
        Read::Absent { .. } => Err(fail(
            StoreErrorCode::ReferenceMissing,
            "Node row references a principal or object not imported yet",
        )),
        Read::Unreadable { reason, .. } => Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => Err(fail(StoreErrorCode::Unreadable, what)),
    }
}
fn event(
    cx: &NodeContext,
    actor: Actor,
    key: &str,
    ts: i64,
    session: Option<SessionId>,
    body: EventBody<InputText>,
) -> StoreResult<NewEvent> {
    Ok(NewEvent {
        header: EventHeader {
            event: event_id(&cx.admission.scope, key)?,
            scope: cx.admission.scope.clone(),
            actor,
            session,
            origin: cx.store.id.clone(),
            door: Door::Import,
            occurred_at_us: ts,
            cause: None,
            supersedes: None,
        },
        body,
    })
}
fn seen<R: Snapshot>(read: &mut R, cx: &NodeContext, id: EventId) -> StoreResult<bool> {
    match read.event(id)? {
        Read::Present { value } => {
            if value.header.door != Door::Import {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "an existing event identity is not this imported history",
                ));
            }
            let cause = value.header.cause.ok_or_else(|| {
                fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "imported event has no retained source correspondence",
                )
            })?;
            match read.event(cause)? {
                Read::Present { value } if matches!(&value.body,EventBody::LegacyRetained{source,..} if source.sha256==cx.source.sha256) => {
                    Ok(true)
                }
                Read::Present { .. } | Read::Absent { .. } => Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "the existing original identity has different or missing source provenance",
                )),
                Read::Unreadable { source, reason, .. } => Err(fail(
                    StoreErrorCode::Unreadable,
                    format!("{source}: {reason}"),
                )),
                Read::Unknown { what } => Err(fail(StoreErrorCode::Unreadable, what)),
            }
        }
        Read::Absent { .. } => Ok(false),
        Read::Unreadable { reason, .. } => Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => Err(fail(StoreErrorCode::Unreadable, what)),
    }
}
pub fn decode<R: ImportSnapshot>(
    cx: &NodeContext,
    read: &mut R,
    kind: NodeKind,
    row: &Value,
) -> StoreResult<DecodedRow> {
    match kind {
        NodeKind::Projects => registration::project(cx, read, row),
        NodeKind::Owners => registration::owner(cx, read, row),
        NodeKind::Profiles => profile::profiles(cx, read, row),
        NodeKind::Messages => message::decode(cx, read, row),
        NodeKind::Ledger => ledger::decode(cx, read, row),
        NodeKind::WorkingState => working::decode(cx, read, row),
        NodeKind::Turns => turns::decode(cx, read, row),
    }
}

fn fail(code: StoreErrorCode, cause: impl Into<String>) -> Box<StoreError> {
    Box::new(StoreError { code, cause: cause.into(), detail: StoreDetail::None,
        remedy: se_types::Remedy { text: "Preserve the source and correct this exact row or its prerequisite before retrying.".into(), command: None }, retry: se_types::Retry::Never })
}
fn invalid(error: impl std::fmt::Display) -> Box<StoreError> {
    fail(StoreErrorCode::EventInvalid, error.to_string())
}
fn source_revision(value: u64) -> StoreResult<Revision> {
    std::num::NonZeroU64::new(value)
        .map(|value| Revision { value })
        .ok_or_else(|| invalid("revision must be positive"))
}
fn actor_id(actor: &Actor) -> &str {
    match actor {
        Actor::Human(id) => id.as_str(),
        Actor::Agent(id) => id.as_str(),
    }
}

/// Physical rows normally hold one operation; profile documents hold many entries.
pub fn units(kind: NodeKind, row: Option<&Value>) -> u64 {
    if matches!(kind, NodeKind::Profiles)
        && let Some(rows) = row.and_then(|row| {
            row.as_array()
                .or_else(|| row.get("seats").and_then(Value::as_array))
        })
    {
        return rows.len() as u64;
    }
    1
}
