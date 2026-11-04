//! Provider metadata is durable capture evidence, separate from chat prose.
use crate::{commit::Cx, scope, store_error::store_error};
use schemars::JsonSchema;
use se_store::{EventBody, Snapshot, StoredEvent, StoredText};
use se_types::{AgentId, Body, EventId, Read, Result, SeError, SessionId};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub offset: u64,
    pub length: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: String,
    pub kind: String,
    pub subtype: Option<String>,
    pub position: Position,
    pub kind_truncated: bool,
    pub subtype_truncated: bool,
}
impl Record {
    pub fn new(kind: &str, subtype: Option<&str>) -> Self {
        let label = |v: &str| v.chars().take(128).collect::<String>();
        let k = label(kind);
        let sub = subtype.map(label);
        Self {
            schema: "se.transcript-event/v1".into(),
            kind_truncated: k.len() != kind.len(),
            subtype_truncated: subtype
                .zip(sub.as_deref())
                .is_some_and(|(a, b)| a.len() != b.len()),
            kind: k,
            subtype: sub,
            position: Position {
                offset: 0,
                length: 0,
            },
        }
    }
    pub fn is_compaction(&self) -> bool {
        self.kind == "compact_boundary"
            || self.kind == "system" && self.subtype.as_deref() == Some("compact_boundary")
    }
    pub fn body(&self) -> Result<Body> {
        Body::new(
            serde_json::to_string(self)
                .map_err(|e| scope::unreadable("transcript metadata", &e.to_string()))?,
        )
    }
    pub fn decode(text: &str) -> Result<Self> {
        let value: Self = serde_json::from_str(text)
            .map_err(|e| scope::unreadable("transcript metadata", &e.to_string()))?;
        if value.schema != "se.transcript-event/v1"
            || value.kind.len() > 512
            || value.subtype.as_ref().is_some_and(|s| s.len() > 512)
        {
            return Err(SeError::invalid(
                "transcript metadata",
                "the bounded v1 record schema",
            ));
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TranscriptEvent {
    pub event_id: EventId,
    pub session_id: SessionId,
    #[serde(flatten)]
    pub record: Record,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct View {
    pub transcript_events: Read<Vec<TranscriptEvent>>,
    /// Exact count omitted from the newest twenty records.
    pub transcript_events_omitted: Read<u64>,
    pub last_compaction: Read<TranscriptEvent>,
}
impl Default for View {
    fn default() -> Self {
        Self {
            transcript_events: Read::Unknown {
                what: "Transcript metadata has not been read".into(),
            },
            transcript_events_omitted: Read::Unknown {
                what: "Transcript metadata has not been counted".into(),
            },
            last_compaction: Read::Unknown {
                what: "Compaction metadata has not been read".into(),
            },
        }
    }
}
fn event(value: StoredEvent) -> Result<TranscriptEvent> {
    let EventBody::SessionTurn {
        session,
        role: se_store::Role::System,
        text: StoredText::Present(text),
        vendor_ref,
        evidence,
        ..
    } = value.body
    else {
        return Err(scope::unreadable(
            "transcript metadata",
            "the stored metadata body is unavailable",
        ));
    };
    if !vendor_ref.starts_with(se_store::TRANSCRIPT_EVENT_PREFIX) {
        return Err(scope::unreadable(
            "transcript metadata",
            "the stored identity is not a provider metadata record",
        ));
    }
    let record = Record::decode(text.as_str())?;
    let end = record
        .position
        .offset
        .checked_add(record.position.length)
        .ok_or_else(|| SeError::invalid("transcript position", "a bounded native range"))?;
    if record.position.length == 0
        || record.position.offset < evidence.offset
        || Some(end) != evidence.offset.checked_add(evidence.length)
    {
        return Err(scope::unreadable(
            "transcript metadata",
            "the recorded position differs from native source evidence",
        ));
    }
    Ok(TranscriptEvent {
        event_id: value.header.event,
        session_id: session,
        record,
    })
}
pub(super) fn read<R: Snapshot>(
    agent: &AgentId,
    session: Option<SessionId>,
    cx: &mut Cx<'_, R>,
) -> View {
    let result = (|| {
        let value = cx
            .read
            .transcript_events(
                agent.clone(),
                session,
                super::continuity::metadata_budget()?,
            )
            .map_err(|e| store_error(&e))?;
        let events = value
            .events
            .into_iter()
            .map(event)
            .collect::<Result<Vec<_>>>()?;
        let last = match value.last_compaction {
            Read::Present { value } => Read::Present {
                value: event(value)?,
            },
            Read::Absent { checked } => Read::Absent { checked },
            Read::Unknown { what } => Read::Unknown { what },
            Read::Unreadable {
                source,
                reason,
                error,
            } => Read::Unreadable {
                source,
                reason,
                error,
            },
        };
        Ok::<_, SeError>(View {
            transcript_events: Read::Present { value: events },
            transcript_events_omitted: Read::Present {
                value: value.omitted,
            },
            last_compaction: last,
        })
    })();
    result.unwrap_or_else(|error| View {
        transcript_events: Read::Unreadable {
            source: "transcript metadata".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.body.clone())),
        },
        transcript_events_omitted: Read::Unreadable {
            source: "transcript metadata count".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.body.clone())),
        },
        last_compaction: Read::Unreadable {
            source: "compaction metadata".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.body)),
        },
    })
}
