use super::{RemoteAttribution, RemoteCursorSet, RemoteTarget};
use crate::{Cursor, LifecycleId, MessageId, Omission, Page, Provider, Read, Receipt, SessionId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteAgentStatus {
    Running {
        session: SessionId,
        lifecycle: LifecycleId,
    },
    Starting,
    Recovering,
    Stopped,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteAgentView {
    pub target: RemoteTarget,
    pub project_name: String,
    pub agent_name: String,
    pub provider: Provider,
    pub status: Read<RemoteAgentStatus>,
    pub pending: Read<u64>,
}
/// Wire responses add one schema to the same body consumed by local CLI/MCP.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemoteResponse<T> {
    pub schema: String,
    #[serde(flatten)]
    pub body: T,
}
impl<T> std::ops::Deref for RemoteResponse<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.body
    }
}
impl<T> std::ops::DerefMut for RemoteResponse<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.body
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteListBody {
    pub agents: Page<RemoteAgentView>,
}
pub type RemoteListResult = RemoteResponse<RemoteListBody>;
impl RemoteListResult {
    pub const SCHEMA: &str = "stateengine.remote-list/v1";
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteLaunchStarted {
    pub target: RemoteTarget,
    pub session: SessionId,
    pub lifecycle: LifecycleId,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteLaunchBody {
    pub outcome: RemoteLaunchOutcome,
    pub attribution: RemoteAttribution,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteLaunchOutcome {
    Running {
        receipt: Receipt<RemoteLaunchStarted>,
    },
    Pending {
        launch: RemoteLaunchStarted,
        idempotency_key: crate::IdempotencyKey,
        setup_needed: bool,
    },
}
pub type RemoteLaunchResult = RemoteResponse<RemoteLaunchBody>;
impl RemoteLaunchResult {
    pub const SCHEMA: &str = "stateengine.remote-launch/v1";
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTurnRole {
    User,
    Assistant,
    Tool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePreview {
    pub text: String,
    pub complete: bool,
    pub omitted_utf8_bytes: Omission,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteDeliveryState {
    Pending,
    Offered,
    Delivered,
    Read,
    Acted,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteDurableEvent {
    Status {
        status: RemoteAgentStatus,
    },
    Message {
        message: MessageId,
        delivery: RemoteDeliveryState,
    },
    Turn {
        item_id: String,
        role: RemoteTurnRole,
        preview: RemotePreview,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteLiveItem {
    pub item_id: String,
    pub role: RemoteTurnRole,
    pub preview: RemotePreview,
}
/// Optional monotonic calibration; no wall-clock synchronization is assumed.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteObservationClock {
    pub epoch: [u8; 16],
    pub sampled_at_us: i64,
    pub source_bracket_us: Option<u64>,
    /// Native source-machine clock sampled immediately before broker release.
    /// Only a native client on that same machine may subtract this timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_released_at_us: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteObservationTime {
    pub at_us: i64,
    /// Filled at the source broker's release, including stream queue delay.
    /// The native terminal adds broker-release-to-flush time to this estimate.
    /// Clock drift and independent suspend are unbounded; None means unavailable.
    pub age_estimate_us: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteWatchRecord {
    Snapshot {
        view: Box<RemoteListResult>,
    },
    Durable {
        target: RemoteTarget,
        cursor: Cursor,
        event: RemoteDurableEvent,
    },
    Provisional {
        target: RemoteTarget,
        cursor: Cursor,
        item: RemoteLiveItem,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observation: Option<RemoteObservationTime>,
    },
    Gap {
        target: RemoteTarget,
        reason: String,
        reset_required: bool,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteWatchBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_clock: Option<RemoteObservationClock>,
    pub records: Vec<RemoteWatchRecord>,
    pub cursors: Vec<RemoteCursorSet>,
    pub complete: bool,
    pub omitted_records: Omission,
    pub reset_required: bool,
}
pub type RemoteWatchBatch = RemoteResponse<RemoteWatchBody>;
impl RemoteWatchBatch {
    pub const SCHEMA: &str = "stateengine.remote-watch/v1";
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteSendBody {
    pub receipt: Receipt<MessageId>,
    pub attribution: RemoteAttribution,
    pub delivery: RemoteDeliveryState,
}
pub type RemoteSendResult = RemoteResponse<RemoteSendBody>;
impl RemoteSendResult {
    pub const SCHEMA: &str = "stateengine.remote-send/v1";
}
