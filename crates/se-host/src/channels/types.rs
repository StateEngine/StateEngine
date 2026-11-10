//! Native channel control/readback contract; no credential bytes cross this API.
use super::ReceiveCoverage;
use se_types::{EventId, IdempotencyKey, MessageId, SessionId};
use serde::{Deserialize, Serialize};

pub use se_store::channel::{
    BotIdentity, ChannelId, ChannelPolicy, ChannelTarget, Connector, CredentialId, CredentialRef,
    ExternalId, PhoneIdentity, ReceiptId, ReceiveCursor,
};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PairingPresentation {
    Challenge {
        revision: u64,
        expires_at_us: i64,
    },
    AwaitingApproval {
        revision: u64,
        expires_at_us: i64,
        phone: PhoneIdentity,
    },
    Paired {
        revision: u64,
        phone: PhoneIdentity,
    },
    Expired {
        revision: u64,
        expired_at_us: i64,
    },
    Revoked {
        revision: u64,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectionHealth {
    Connected {
        last_poll_at_us: Option<i64>,
    },
    Retrying {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,64>")]
        code: String,
        retry_at_us: i64,
    },
    Unavailable {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,64>")]
        code: String,
    },
    ReceiverNotRunning {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,1024>")]
        reason: String,
    },
    Disconnected,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialRemoval {
    Retained,
    Removed,
    Pending {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,64>")]
        code: String,
    },
    Unknown {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,64>")]
        code: String,
    },
}
/// Full recovery state: a reopened surface needs no cached connection revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSnapshot {
    pub id: ChannelId,
    pub connector: Connector,
    pub revision: u64,
    pub target: ChannelTarget,
    pub bot: BotIdentity,
    pub policy: ChannelPolicy,
    pub pairing: PairingPresentation,
    pub health: ConnectionHealth,
    pub receive_coverage: ReceiveCoverage,
    pub credential_removal: CredentialRemoval,
    pub observed_at_us: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectChannel {
    #[serde(default, skip_serializing_if = "Connector::is_telegram")]
    pub connector: Connector,
    pub credential: CredentialRef,
    pub target: ChannelTarget,
    #[serde(default)]
    pub policy: ChannelPolicy,
    pub key: IdempotencyKey,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelControl {
    pub connection: ChannelId,
    pub expected_revision: u64,
    pub key: IdempotencyKey,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmPairing {
    pub connection: ChannelId,
    /// The shown phone identity and target are bound to this exact revision.
    pub expected_pairing_revision: u64,
    pub key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedFact {
    pub event: EventId,
    pub at_us: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NoticeFact {
    Pending {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,1024>")]
        reason: String,
    },
    Received {
        event: EventId,
        session: SessionId,
        #[serde(deserialize_with = "super::validation::bounded_string::<_,512>")]
        conversation: String,
        at_us: i64,
    },
    Unknown {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,64>")]
        code: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderOutput {
    Queued,
    Sent {
        provider_message: ExternalId,
        at_us: i64,
    },
    Unknown {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,64>")]
        code: String,
    },
    Failed {
        #[serde(deserialize_with = "super::validation::bounded_string::<_,64>")]
        code: String,
    },
    Revoked,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyFact {
    pub message: MessageId,
    pub committed: CommittedFact,
    #[serde(alias = "telegram")]
    pub delivery: ProviderOutput,
    #[serde(default)]
    pub provider_messages: Vec<ExternalId>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelReceipt {
    pub id: ReceiptId,
    pub connection: ChannelId,
    pub message: MessageId,
    pub target: ChannelTarget,
    pub saved: CommittedFact,
    pub notice: NoticeFact,
    pub read: Option<CommittedFact>,
    #[serde(deserialize_with = "super::validation::bounded_rows")]
    pub replies: Vec<ReplyFact>,
    pub replies_omitted: u64,
    pub delay: Option<DelayFact>,
    pub resume: Option<ResumePresentation>,
    pub observed_at_us: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DelayFact {
    NotReadYet {
        elapsed_seconds: u64,
        #[serde(deserialize_with = "super::validation::bounded_string::<_,1024>")]
        reason: String,
    },
    ReadNoReplyYet {
        elapsed_seconds: u64,
        #[serde(deserialize_with = "super::validation::bounded_string::<_,1024>")]
        reason: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectChannels {
    pub connection: Option<ChannelId>,
    pub receipt: Option<ReceiptId>,
    pub cursor: Option<String>,
    pub wait_until_us: Option<i64>,
}
/// Dedicated native Owner IPC frames, never ordinary operations or agent tools.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ChannelRequest {
    CredentialCatalog,
    Capabilities,
    Targets(ChannelTargets),
    #[serde(alias = "connect_telegram")]
    Connect(ConnectChannel),
    Inspect(InspectChannels),
    ConfirmPairing(ConfirmPairing),
    RestartPairing(ChannelControl),
    Disconnect(ChannelControl),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelPage {
    #[serde(deserialize_with = "super::validation::bounded_rows")]
    pub connections: Vec<ChannelSnapshot>,
    #[serde(deserialize_with = "super::validation::bounded_rows")]
    pub receipts: Vec<ChannelReceipt>,
    #[serde(deserialize_with = "super::validation::bounded_string::<_,512>")]
    pub cursor: String,
    #[serde(deserialize_with = "super::validation::bounded_string::<_,512>")]
    pub watch_cursor: String,
    pub complete: bool,
    pub omitted: u64,
    pub recent_rejections: Option<RejectionWindow>,
}

/// Opaque references from the native credential owner, never token material.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCatalog {
    #[serde(deserialize_with = "super::validation::bounded_rows")]
    pub credentials: Vec<CredentialRef>,
    pub complete: bool,
    pub omitted: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelTargets {
    pub project: se_types::ProjectId,
    pub after: Option<se_types::Cursor>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelAgentChoice {
    pub target: ChannelTarget,
    pub saved: se_core::ops::AgentRow,
    pub profile_revision: u64,
    pub confirmed_resume_supported: bool,
    pub resume_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumePresentation {
    pub state: String,
    pub expires_at_us: i64,
    pub code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputRejection {
    pub update: ExternalId,
    pub reason: se_store::channel::Rejection,
    pub at_us: i64,
    #[serde(alias = "telegram")]
    pub delivery: ProviderOutput,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectionWindow {
    #[serde(deserialize_with = "super::validation::bounded_rows")]
    pub items: Vec<InputRejection>,
    pub more: bool,
}
