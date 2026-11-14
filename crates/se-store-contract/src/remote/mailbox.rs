//! Public provenance for native source-side return delivery; no credentials.
use se_types::{Cursor, MessageId, remote::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailContact {
    pub source: RemoteAgentAddress,
    pub peer: RemoteHostId,
    pub target: RemoteTarget,
    pub original: MessageId,
    /// A local remote principal allocated for this exact contact route. It is
    /// never the foreign machine's delegated principal or a local Owner.
    pub principal: RemotePrincipalId,
    pub alias: String,
    pub request_key: se_types::IdempotencyKey,
    pub original_grant: RemoteGrantId,
    pub local_reply: Option<MessageId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingContact {
    pub source: RemoteAgentAddress,
    pub peer: RemoteHostId,
    pub target: RemoteTarget,
    pub alias: String,
    pub request_key: se_types::IdempotencyKey,
    pub original_grant: RemoteGrantId,
    pub local_reply: Option<MessageId>,
}

#[derive(Clone, Debug)]
pub struct MailRoute {
    pub peer: RemoteHostId,
    pub target: RemoteTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnAttribution {
    pub message: MessageId,
    pub peer_message: MessageId,
    pub original: MessageId,
    pub source: RemoteAgentAddress,
    pub sender: RemoteAgentAddress,
    pub principal: RemotePrincipalId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MailboxChange {
    Pending {
        record: PendingContact,
    },
    Contact {
        record: MailContact,
    },
    Received {
        record: ReturnAttribution,
    },
    Checkpoint {
        source: RemoteAgentAddress,
        peer: RemoteHostId,
        target: RemoteTarget,
        grant: RemoteGrantId,
        cursor: Cursor,
    },
}
