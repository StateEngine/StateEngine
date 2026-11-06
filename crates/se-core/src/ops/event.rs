//! Exact public history reads. Snapshot enforces project/privacy and excludes
//! runtime-private facts before any public payload is constructed.
use super::{ActorRef, Named, Writer, inputs::Validate, receipt};
use crate::{commit::Cx, scope, store_error::store_error};
use schemars::JsonSchema;
use se_store::{EventBody, PositionPurpose, Scope, Snapshot, StoredEvent, WriterModeValue};
use se_types::{Cursor, EventId, ProjectId, Read, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventRead {
    pub event_id: String,
}
impl Validate for EventRead {
    fn validate(&self) -> Result<()> {
        super::inputs::bounded("event_id", &self.event_id, 512, false)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HistoryEvent {
    pub event_id: EventId,
    pub position: Cursor,
    pub kind: String,
    pub recorded_at: String,
    pub project: Named<ProjectId>,
    pub actor: ActorRef,
    pub writer: Writer,
    pub read_at: Cursor,
    pub payload: serde_json::Value,
}
/// Present events retain Appendix A.14's flat family. Other states preserve the
/// canonical Read shape rather than manufacturing a payload or not-found error.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum EventOutput {
    Present(HistoryEvent),
    Other(Read<HistoryEvent>),
}
pub fn read<R: Snapshot>(input: EventRead, cx: &mut Cx<'_, R>) -> Result<EventOutput> {
    input.validate()?;
    scope::project(cx.admission)?;
    let registry = cx.read.legacy_registry().map_err(|e| store_error(&e))?;
    let id = EventId::from_legacy(input.event_id.clone())
        .or_else(|_| EventId::from_registered_legacy(input.event_id, &registry))?;
    drop(registry);
    let event = match cx.read.event(id).map_err(|e| store_error(&e))? {
        Read::Present { value } => value,
        Read::Absent { checked } => return Ok(EventOutput::Other(Read::Absent { checked })),
        Read::Unreadable {
            source,
            reason,
            error,
        } => {
            return Ok(EventOutput::Other(Read::Unreadable {
                source,
                reason,
                error,
            }));
        }
        Read::Unknown { what } => return Ok(EventOutput::Other(Read::Unknown { what })),
    };
    Ok(EventOutput::Present(project_event(event, cx)?))
}

/// Shared complete public projection for exact reads and paged history. The
/// input must come from this same admitted snapshot; scope is checked again.
pub fn project_event<R: Snapshot>(event: StoredEvent, cx: &mut Cx<'_, R>) -> Result<HistoryEvent> {
    let project = scope::project(cx.admission)?.clone();
    if event.header.scope != Scope::Project(project.clone()) {
        return Err(scope::unreadable(
            "event scope",
            "exact event returned outside the authorized project",
        ));
    }
    let project_record = scope::require_present(
        cx.read
            .project(project.clone())
            .map_err(|e| store_error(&e))?,
        "event project metadata",
        "Read the event's project metadata in the same data home, then retry this exact event ID.",
    )?;
    let metadata = if let EventBody::ProjectRemoved {
        project: removed, ..
    } = &project_record.current.body
    {
        if removed != &project {
            return Err(scope::unreadable(
                "event project",
                "tombstone identity differs from the admitted project",
            ));
        }
        &project_record
            .original
            .as_deref()
            .ok_or_else(|| {
                scope::unreadable("event project", "retained registration is unavailable")
            })?
            .body
    } else {
        &project_record.current.body
    };
    let name = match metadata {
        EventBody::ProjectRegistered {
            project: registered,
            name,
            ..
        }
        | EventBody::ProjectUpdated {
            project: registered,
            name,
            ..
        }
        | EventBody::ProjectMoved {
            project: registered,
            name,
            ..
        } if registered == &project => name.clone(),
        _ => {
            return Err(scope::unreadable(
                "event project",
                "matching project registration metadata is unavailable",
            ));
        }
    };
    let actor = receipt::actor_ref(cx.read, &event.header.actor)?;
    let position = cx
        .read
        .position_cursor(&event.position, PositionPurpose::History)
        .map_err(|e| store_error(&e))?;
    // The checked source is this exact visible event, not a private/global head.
    let read_at = cx
        .read
        .position_cursor(&event.position, PositionPurpose::Checked)
        .map_err(|e| store_error(&e))?;
    let (kind, mut payload) = payload::public(&event, cx.read)?;
    if event.header.door == se_store::Door::Import {
        let fields = payload.as_object_mut().ok_or_else(|| {
            scope::unreadable("imported history", "public payload is not an object")
        })?;
        fields.insert(
            "occurred_at".into(),
            serde_json::to_value(receipt::timestamp(event.header.occurred_at_us)?)
                .map_err(|e| scope::unreadable("historical source time", &e.to_string()))?,
        );
    }
    let writer = match event.writer.kind() {
        se_store::WriterKind::Direct => Writer::Direct,
        se_store::WriterKind::Host { generation } => Writer::Host {
            host_generation: generation.to_string(),
        },
    };
    Ok(HistoryEvent {
        event_id: event.header.event,
        position,
        kind: kind.into(),
        recorded_at: receipt::timestamp(event.recorded_at_us)?,
        project: Named { id: project, name },
        actor,
        writer,
        read_at,
        payload,
    })
}

#[path = "event/payload.rs"]
mod payload;
