//! Cursor-resumable push event stream (`events.subscribe` / `IpcRequest::Subscribe`)
//! over local IPC. Wire types compile without the `listener` feature so IPC
//! clients can open and consume event streams cleanly.
use se_types::{AgentId, EventId, ProjectId, Result, SeError};
use serde::{Deserialize, Serialize};

#[cfg(feature = "listener")]
pub(crate) mod admit;
#[cfg(feature = "listener")]
pub(crate) mod cursor;
#[cfg(feature = "listener")]
pub(crate) mod project;
#[cfg(feature = "listener")]
pub(crate) mod stream;

#[cfg(feature = "listener")]
pub(crate) use admit::AdmittedSubscribe;

/// Capability token advertised by hosts supporting `IpcRequest::Subscribe`.
pub const EVENTS_SUBSCRIBE_CAPABILITY: &str = "events.subscribe";

/// Wire schema identifier carried on every streamed `OperationOutput` frame.
pub const EVENT_STREAM_SCHEMA: &str = "se.event-stream/v1";

/// Default heartbeat interval so clients detect half-open sockets cleanly.
pub const DEFAULT_HEARTBEAT_SECS: u64 = 10;

/// Maximum buffered frames per subscriber before emitting `lagged` and closing.
pub const MAX_SUBSCRIBER_QUEUE: usize = 256;

/// Minimum caller-requested `max_batch_bytes` (must fit a single control frame).
pub const MIN_BATCH_BYTES: u32 = 1024;

/// Closed event-stream kind filter for `events.subscribe`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EventStreamKind {
    #[serde(rename = "mail.notice")]
    MailNotice,
    #[serde(rename = "agent.state")]
    AgentState,
    #[serde(rename = "assignment")]
    Assignment,
    #[serde(rename = "decision")]
    Decision,
    #[serde(rename = "session.hold")]
    SessionHold,
    #[serde(rename = "session.revoke")]
    SessionRevoke,
}

impl EventStreamKind {
    pub const ALL: &[Self] = &[
        Self::MailNotice,
        Self::AgentState,
        Self::Assignment,
        Self::Decision,
        Self::SessionHold,
        Self::SessionRevoke,
    ];
}

/// Request payload for `IpcRequest::Subscribe`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Vec<EventStreamKind>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_batch_bytes: Option<u32>,
}

impl SubscribeRequest {
    pub fn validate(&self) -> Result<()> {
        if let Some(cursor) = &self.after_cursor
            && (cursor.is_empty() || cursor.len() > 512)
        {
            return Err(SeError::invalid(
                "stale_cursor",
                "a nonempty opaque event-stream cursor of at most 512 bytes",
            ));
        }
        if let Some(filter) = &self.filter
            && filter.len() > 16
        {
            return Err(SeError::invalid(
                "events.subscribe filter",
                "at most 16 event stream kinds",
            ));
        }
        if let Some(bytes) = self.max_batch_bytes
            && (bytes < MIN_BATCH_BYTES || bytes as usize > crate::client::wire::MAX_FRAME_BYTES)
        {
            return Err(SeError::invalid(
                "events.subscribe max_batch_bytes",
                &format!(
                    "a byte limit between {MIN_BATCH_BYTES} and {}",
                    crate::client::wire::MAX_FRAME_BYTES
                ),
            ));
        }
        Ok(())
    }
}

/// One ordered event frame pushed over `events.subscribe`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventPushFrame {
    pub cursor: String,
    pub event_id: EventId,
    pub kind: EventStreamKind,
    pub occurred_at_us: i64,
    pub payload: serde_json::Value,
}

/// Control frames pushed on `events.subscribe` for liveness and backpressure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlFrame {
    Heartbeat { head_cursor: String },
    Lagged { missed_through_cursor: String },
}

/// Every frame emitted inside `OperationOutput { schema: "se.event-stream/v1", value }`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SubscribeFrame {
    Event(EventPushFrame),
    Control(ControlFrame),
}
