//! Owner-approved external seat claims, fenced leases, and blocking mail wait.
//! Wire types compile without the `listener` feature so IPC clients can speak
//! the closed external seat protocol cleanly.
use se_types::{AgentId, Generation, MessageId, NativePath, ProjectId, Result, SeError, SessionId};
use serde::{Deserialize, Serialize};

#[cfg(feature = "listener")]
pub(crate) mod commit;
#[cfg(feature = "listener")]
pub(crate) mod dispatch;
#[cfg(feature = "listener")]
pub(crate) mod lifecycle;
#[cfg(feature = "listener")]
pub(crate) mod registry;
#[cfg(feature = "listener")]
pub(crate) mod wait;

#[cfg(feature = "listener")]
pub(crate) use registry::{
    ActiveLease, ClaimApprovalDelivery, ExternalRegistry, PendingClaimHandle,
};

/// Dedicated credential purpose for owner-approved external seats.
/// Separate from `session` (managed CLI/IPC) and `http` (managed loopback MCP).
pub const EXTERNAL_SESSION_CAPABILITY: &str = "external_session";

/// Closed Phase 1 scope identifier bound into every pending claim.
pub const EXTERNAL_SEAT_SCOPE: &str = "external-seat-v1";

/// Default pending claim lifetime before automatic expiry (5 minutes).
pub const CLAIM_TTL_SECS: u64 = 300;

/// Default external seat lease lifetime (8 hours).
pub const EXTERNAL_LEASE_TTL_SECS: u64 = 8 * 60 * 60;

/// Maximum blocking wait timeout accepted by `se msg wait` (5 minutes).
pub const MAX_WAIT_TIMEOUT_MS: u64 = 300_000;

/// Default blocking wait timeout when omitted (25 seconds).
pub const DEFAULT_WAIT_TIMEOUT_MS: u64 = 25_000;

/// Handshake payload presented by a dedicated stdio MCP bridge (`se mcp --as <name>`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalClaimBootstrap {
    pub project: Option<ProjectId>,
    pub cwd: NativePath,
    pub agent: String,
    pub connection_nonce: [u8; 32],
}

impl ExternalClaimBootstrap {
    pub fn validate(&self) -> Result<()> {
        if self.agent.is_empty() || self.agent.len() > 64 {
            return Err(SeError::invalid(
                "external seat agent",
                "a nonempty agent name or ID of at most 64 characters",
            ));
        }
        if self.connection_nonce == [0; 32] {
            return Err(SeError::invalid(
                "external seat nonce",
                "a fresh nonzero 32-byte connection nonce",
            ));
        }
        Ok(())
    }
}

/// Closed native IPC request family for external seat lifecycle and wait.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalRequest {
    /// Bridge reads back the pending claim ID opened by its `ExternalClaim` handshake.
    ClaimOpen,
    /// Bridge parks on its own native connection awaiting out-of-band Owner approval.
    ClaimWait { claim_id: String },
    /// Owner lists pending claims and active external seat leases.
    List { project: Option<ProjectId> },
    /// Owner approves a pending claim once, minting the external seat atomically.
    Approve { claim_id: String },
    /// Owner revokes an active external seat by agent name/ID (or exact session).
    Revoke {
        project: Option<ProjectId>,
        agent: String,
    },
    /// Separate authenticated blocking mail wait reusing the host's recipient-scoped registry.
    MailWait {
        project: Option<ProjectId>,
        agent: Option<String>,
        after: Option<String>,
        timeout_ms: Option<u64>,
    },
}

impl ExternalRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ClaimOpen => Ok(()),
            Self::ClaimWait { claim_id } | Self::Approve { claim_id } => {
                validate_claim_id(claim_id)
            }
            Self::List { .. } => Ok(()),
            Self::Revoke { agent, .. } => {
                if agent.is_empty() || agent.len() > 64 {
                    return Err(SeError::invalid(
                        "external revoke target",
                        "a nonempty agent name or ID",
                    ));
                }
                Ok(())
            }
            Self::MailWait {
                agent,
                after,
                timeout_ms,
                ..
            } => {
                if let Some(agent) = agent
                    && (agent.is_empty() || agent.len() > 64)
                {
                    return Err(SeError::invalid(
                        "mail wait agent",
                        "a nonempty agent name or ID",
                    ));
                }
                if let Some(after) = after
                    && (after.is_empty() || after.len() > 512)
                {
                    return Err(SeError::invalid("mail wait cursor", "a bounded cursor"));
                }
                if let Some(ms) = timeout_ms
                    && (*ms == 0 || *ms > MAX_WAIT_TIMEOUT_MS)
                {
                    return Err(SeError::invalid(
                        "mail wait timeout",
                        "a timeout between 1ms and 300000ms",
                    ));
                }
                Ok(())
            }
        }
    }
}

pub fn validate_claim_id(claim_id: &str) -> Result<()> {
    if !claim_id.starts_with("claim_")
        || claim_id.len() < 14
        || claim_id.len() > 80
        || !claim_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(SeError::invalid(
            "external claim ID",
            "a valid `claim_<hex>` identifier from `se external list`",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingClaimView {
    pub claim_id: String,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub scope: String,
    pub peer_pid: u32,
    pub host_generation: Generation,
    pub expires_at_us: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveExternalLeaseView {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub session_id: SessionId,
    pub lease_generation: u64,
    pub peer_pid: u32,
    pub host_generation: Generation,
    pub expires_at_us: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalListOutput {
    pub pending_claims: Vec<PendingClaimView>,
    pub active_leases: Vec<ActiveExternalLeaseView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalClaimOpenOutput {
    pub claim_id: String,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub scope: String,
    pub expires_at_us: i64,
}

/// Delivered exclusively over the waiting bridge's verified native IPC channel.
/// Never written to stdout, logs, prompts, argv, env, or repo settings.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExternalClaimApproved {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub session_id: SessionId,
    pub lease_generation: u64,
    pub expires_at_us: i64,
    pub capability: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalApproveOutput {
    pub claim_id: String,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub session_id: SessionId,
    pub lease_generation: u64,
    pub expires_at_us: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalRevokeOutput {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub session_id: SessionId,
    pub lease_generation: Option<u64>,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMailWaitOutput {
    pub status: String,
    pub session_id: SessionId,
    pub ids: Vec<MessageId>,
    pub cursor: se_types::Cursor,
    pub complete: bool,
}
