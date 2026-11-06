//! Non-secret channel facts stored atomically with ordinary mail.
mod ids;
mod resume;
pub use ids::{ActionId, ChannelId, CredentialId, OutputId, ReceiptId};
pub use resume::{ResumeAction, ResumeTarget};
use se_types::{AgentId, HumanId, MessageId, ProjectId, StoreId};
use serde::{Deserialize, Serialize};

pub const MAX_CONNECTIONS: usize = 100;
pub const MAX_PENDING: usize = 1000;
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub store: StoreId,
    pub owner: HumanId,
    pub id: CredentialId,
    pub revision: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelTarget {
    pub project: ProjectId,
    pub agent: AgentId,
    pub selection_revision: u64,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelPolicy {
    #[default]
    SaveOnly,
    ConfirmResume {
        profile: String,
        profile_revision: u64,
        cost_limit: Option<u64>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotIdentity {
    pub id: i64,
    pub username: String,
    pub display_name: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneIdentity {
    pub subject: i64,
    pub private_chat: i64,
    pub display_name: String,
    pub username: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Pairing {
    Challenge {
        digest: [u8; 32],
        expires_at_us: i64,
    },
    AwaitingApproval {
        phone: PhoneIdentity,
        expires_at_us: i64,
    },
    Paired {
        phone: PhoneIdentity,
    },
    Revoked,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub id: ChannelId,
    pub owner: HumanId,
    pub credential: CredentialRef,
    pub target: ChannelTarget,
    pub bot: BotIdentity,
    pub policy: ChannelPolicy,
    pub pairing: Pairing,
    pub revision: u64,
    pub credential_removed: bool,
    pub resume_configuration: Option<[u8; 32]>,
}
/// No provider body, challenge ticket, token or arbitrary diagnostic strings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Connected {
        connection: Connection,
    },
    PairingSeen {
        connection: ChannelId,
        expected: u64,
        digest: [u8; 32],
        phone: PhoneIdentity,
    },
    PairingConfirmed {
        connection: ChannelId,
        expected: u64,
    },
    PairingRestarted {
        connection: ChannelId,
        expected: u64,
        digest: [u8; 32],
        expires_at_us: i64,
    },
    Disconnected {
        connection: ChannelId,
        expected: u64,
    },
    CredentialRemoved {
        connection: ChannelId,
        credential: CredentialRef,
    },
    UpdateHandled {
        connection: ChannelId,
        binding_revision: u64,
        update: i64,
        disposition: Disposition,
    },
    ResumeOffered {
        action: ResumeAction,
    },
    ResumeConfirmed {
        connection: ChannelId,
        action: ActionId,
        subject: i64,
        private_chat: i64,
    },
    ResumeReleased {
        connection: ChannelId,
        action: ActionId,
        session: se_types::SessionId,
    },
    ResumeFailed {
        connection: ChannelId,
        action: ActionId,
        code: String,
    },
    DelayQueued {
        connection: ChannelId,
        binding_revision: u64,
        message: MessageId,
    },
    OutputStarted {
        connection: ChannelId,
        binding_revision: u64,
        output: OutputId,
        expected_attempt: u64,
    },
    OutputFinished {
        connection: ChannelId,
        output: OutputId,
        attempt: u64,
        outcome: OutputOutcome,
    },
}
impl Change {
    pub fn connection(&self) -> &ChannelId {
        match self {
            Self::Connected { connection } => &connection.id,
            Self::ResumeOffered { action } => &action.connection,
            Self::PairingSeen { connection, .. }
            | Self::PairingConfirmed { connection, .. }
            | Self::PairingRestarted { connection, .. }
            | Self::Disconnected { connection, .. }
            | Self::CredentialRemoved { connection, .. }
            | Self::UpdateHandled { connection, .. }
            | Self::ResumeConfirmed { connection, .. }
            | Self::ResumeReleased { connection, .. }
            | Self::ResumeFailed { connection, .. }
            | Self::DelayQueued { connection, .. }
            | Self::OutputStarted { connection, .. }
            | Self::OutputFinished { connection, .. } => connection,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Disposition {
    RejectedPaired {
        reason: Rejection,
        subject: i64,
        private_chat: i64,
    },
    Action {
        action: ActionId,
    },
    Saved {
        receipt: ReceiptId,
        message: MessageId,
        subject: i64,
        private_chat: i64,
    },
    Rejected {
        reason: Rejection,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    Unsupported,
    Unpaired,
    Revoked,
    TooLarge,
    QueueFull,
    Expired,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputOutcome {
    Sent {
        provider_message: i64,
    },
    Unknown,
    /// Only when transport proves no message was released (e.g. Telegram 429).
    Retry {
        after_us: i64,
    },
    Failed {
        reason: se_types::MessagingChannelError,
    },
}
#[derive(Clone, Debug)]
pub struct SavedUpdate {
    pub ordinal: u64,
    pub receipt: ReceiptId,
    pub connection: ChannelId,
    pub message: MessageId,
    pub event: se_types::EventId,
    pub at_us: i64,
}
#[derive(Clone, Debug)]
pub struct Outbound {
    pub connection: ChannelId,
    pub binding_revision: u64,
    pub output: OutputId,
    pub attempt: u64,
    pub at_us: i64,
    pub kind: String,
    pub original: Option<MessageId>,
    pub reply: Option<MessageId>,
    pub state: String,
    pub provider_message: Option<i64>,
    pub retry_at_us: Option<i64>,
    pub rejection: Option<Rejection>,
    pub provider_update: Option<i64>,
    pub failure: Option<se_types::MessagingChannelError>,
}
#[derive(Clone, Debug)]
pub struct ChannelRows<T> {
    pub items: Vec<T>,
    pub after: u64,
    pub omitted: u64,
}
#[derive(Clone, Debug)]
pub struct ReplyRoute {
    pub owner: HumanId,
    pub original: MessageId,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct Version {
    pub store: StoreId,
    pub incarnation: u64,
    pub head: u64,
}

#[derive(Clone, Debug)]
pub struct RejectedInput {
    pub update: i64,
    pub reason: Rejection,
    pub at_us: i64,
    pub output_state: String,
    pub provider_message: Option<i64>,
    pub output_at_us: i64,
    pub failure: Option<se_types::MessagingChannelError>,
}
#[derive(Clone, Debug)]
pub struct RecentRejections {
    pub items: Vec<RejectedInput>,
    pub more: bool,
}
