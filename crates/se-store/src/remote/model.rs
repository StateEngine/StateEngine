//! Durable public authority facts. Machine credentials never enter the store.
use crate::{Revision, StoreId};
use se_types::remote::{
    CredentialDigest, RemoteAttribution, RemoteDeviceId, RemoteGrantId, RemoteHostId,
    RemotePrincipalId, RemoteScope, RemoteSubject, RemoteTarget,
};
use se_types::{MessageId, SessionId};
use serde::{Deserialize, Serialize};

pub const GRANT_INACTIVITY_US: i64 = 30 * 24 * 60 * 60 * 1_000_000;
pub const LEASE_COALESCE_US: i64 = 24 * 60 * 60 * 1_000_000;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    pub grant: RemoteGrantId,
    pub principal: RemotePrincipalId,
    pub device: RemoteDeviceId,
    pub credential_sha256: CredentialDigest,
    pub host: RemoteHostId,
    pub store: StoreId,
    pub subject: RemoteSubject,
    pub scope: RemoteScope,
    pub issued_at_us: i64,
    pub authority_revision: Revision,
    pub state: GrantState,
    pub last_use_at_us: i64,
    pub expires_at_us: i64,
    pub lease_revision: Revision,
}

/// Closed FULL security transitions; no generic configuration or SQL payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityTransition {
    /// Protected native SSH bootstrap; machine authority is not an agent identity.
    Connect {
        grant: Box<GrantRecord>,
    },
    Renew {
        grant: RemoteGrantId,
        authority_revision: Revision,
        expected_lease_revision: Revision,
        proven_use_at_us: i64,
    },
    Revoke {
        grant: RemoteGrantId,
        expected: Revision,
    },
    LaunchPermission {
        change: LaunchPermissionChange,
    },
    /// Existing Owner credential rotation/restore calls this before accepting clients.
    RevokeAll,
}

/// Stored beside the ordinary message in the same atomic transaction.
/// The source session is attribution only, never the target event's local session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAttribution {
    pub message: MessageId,
    pub principal: RemotePrincipalId,
    pub grant: RemoteGrantId,
    pub authority_revision: Revision,
    pub target: RemoteTarget,
    pub expected_session: SessionId,
    pub attribution: RemoteAttribution,
}

/// Separate consent keeps the machine grant's original verbs and targets intact.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPermissionChange {
    pub grant: RemoteGrantId,
    pub target: RemoteTarget,
    pub allowed: bool,
    pub expected: Option<Revision>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPermission {
    pub grant: RemoteGrantId,
    pub target: RemoteTarget,
    pub allowed: bool,
    pub revision: Revision,
}

/// Native C1 proof that this actual remote caller admitted one local lifecycle.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAttribution {
    pub target: RemoteTarget,
    pub expected_profile: Revision,
    pub session: SessionId,
    pub lifecycle: se_types::LifecycleId,
    pub attribution: RemoteAttribution,
}
