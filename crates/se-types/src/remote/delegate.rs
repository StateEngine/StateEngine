//! Remote delegation: one bounded temporary worker beside an Owner-approved
//! destination agent. The anchor's launch consent is the only authority; the
//! worker never widens it.
use super::{RemoteAttribution, RemoteLaunchOutcome, RemoteResponse, RemoteTarget};
use crate::{IdempotencyKey, Provider, Result, SeError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Largest task a remote worker accepts, matching local delegation.
pub const REMOTE_DELEGATE_TASK_BYTES: usize = 16 * 1024;
/// Longest lifetime any worker may have, on either machine.
pub const REMOTE_DELEGATE_MAX_TTL_SECONDS: u32 = 86_400;

/// Create and start one temporary worker in the anchor's project.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteDelegate {
    /// The saved destination agent whose launch consent admits this worker.
    pub target: RemoteTarget,
    /// First prompt the worker receives.
    pub task: String,
    /// Label in the worker name `tmp-<role>-<8hex>` (default `helper`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Destination provider; defaults to the anchor's saved provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// Destination named profile; defaults to the anchor's saved profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Requested lifetime; each machine lowers it to its own cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    pub idempotency_key: IdempotencyKey,
}

impl RemoteDelegate {
    pub fn validate(&self) -> Result<()> {
        if self.task.trim().is_empty() || self.task.len() > REMOTE_DELEGATE_TASK_BYTES {
            return Err(SeError::invalid(
                "remote delegate task",
                "nonempty UTF-8 text of at most 16384 bytes",
            ));
        }
        if let Some(role) = &self.role
            && (role.is_empty()
                || role.len() > 32
                || !role
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err(SeError::invalid(
                "remote delegate role",
                "1..32 ASCII letters, digits, hyphens or underscores",
            ));
        }
        if self
            .profile
            .as_ref()
            .is_some_and(|p| p.is_empty() || p.len() > 64)
        {
            return Err(SeError::invalid(
                "remote delegate profile",
                "a named profile of 1..64 bytes",
            ));
        }
        if self
            .ttl_seconds
            .is_some_and(|t| !(1..=REMOTE_DELEGATE_MAX_TTL_SECONDS).contains(&t))
        {
            return Err(SeError::invalid(
                "remote delegate ttl_seconds",
                "1..86400 seconds",
            ));
        }
        Ok(())
    }
}

/// What the destination saved for the worker, read back from its store.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteDelegateWorker {
    /// The approved agent the worker was admitted under.
    pub anchor: RemoteTarget,
    pub name: String,
    pub provider: Provider,
    pub profile: String,
    pub ttl_seconds: u32,
}

/// The worker's launch outcome names the worker as its target: that project,
/// agent, session and lifecycle are the handle for remote list, watch and send.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteDelegateBody {
    pub outcome: RemoteLaunchOutcome,
    pub worker: RemoteDelegateWorker,
    pub attribution: RemoteAttribution,
}
pub type RemoteDelegateResult = RemoteResponse<RemoteDelegateBody>;
impl RemoteDelegateResult {
    pub const SCHEMA: &str = "stateengine.remote-delegate/v1";
}
