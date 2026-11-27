//! Composite temporary agent delegation (`delegate.start`, `delegate.cancel`)
//! and atomic post-`SessionEnded` completion notice + retirement batch builder.
mod cancel;
mod completion;
mod start;

pub use cancel::plan_cancel;
pub use completion::{CaptureOutcome, CompletionNoticeInput, completion_notice_batch};
pub(crate) use start::{RemoteRequest, Requester, plan_worker, require_delegate_authority};
pub use start::{committed_worker, create_ephemeral_batch, enforce_active_child_cap, plan_start};

use crate::{
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops::{
        AnyOutput,
        inputs::{Validate, bounded},
    },
    ports::{CustodyPlan, Then},
};
use schemars::JsonSchema;
use se_config::config_policy::{ConfigFile, MAX_TTL_SECONDS, Provider};
use se_store::{Actor, EphemeralSpec, PermissionProfile, Snapshot};
use se_types::{
    AgentId, Cursor, IdempotencyKey, Named, NativePath, ProjectId, Result, SeError, SessionId,
};
use serde::{Deserialize, Serialize};

pub(super) const MAX_TASK_BYTES: usize = 16 * 1024;
pub(super) const MAX_HANDOFF_BYTES: u32 = 8 * 1024;
pub(super) const DEFAULT_HANDOFF_BYTES: u32 = 8 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegateHandoff {
    /// Agent name or ID to export context from (optional for bound agents; required for owner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Maximum UTF-8 bytes in the handoff packet (256..=8192, default 8192).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<u32>,
    /// Optional continuity cursor for incremental export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Cursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegateStart {
    /// Initial task prompt delivered to the temporary agent.
    pub task: String,
    /// Short role label used in the temporary name `tmp-<role>-<8hex>` (default: `helper`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Target provider (defaults to configured launch provider).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// Optional native provider or named declarative ACP harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// Optional model override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Named permission profile (validated against `[delegation].allow` for agent callers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Optional cross-model context handoff prepended to `task`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<Box<DelegateHandoff>>,
    /// Optional TTL backstop in seconds (1..=86400; capped at configured `[delegation].ttl_seconds`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    pub idempotency_key: IdempotencyKey,
}

impl Validate for DelegateStart {
    fn validate(&self) -> Result<()> {
        bounded("task", &self.task, MAX_TASK_BYTES, true)?;
        if let Some(role) = &self.role {
            bounded("role", role, 32, false)?;
            if !role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(SeError::invalid(
                    "role",
                    "ASCII letters, digits, hyphen or underscore (1..=32 chars)",
                ));
            }
        }
        if let Some(harness) = &self.harness {
            se_config::config_policy::harness::validate_name(harness)?;
        }
        if let Some(model) = &self.model {
            bounded("model", model, 256, false)?;
        }
        if let Some(profile) = &self.profile {
            bounded("profile", profile, 64, false)?;
        }
        if let Some(handoff) = &self.handoff
            && let Some(budget) = handoff.budget
            && !(256..=MAX_HANDOFF_BYTES).contains(&budget)
        {
            return Err(SeError::invalid(
                "handoff.budget",
                "expected 256..=8192 bytes",
            ));
        }
        if let Some(ttl) = self.ttl_seconds
            && !(1..=MAX_TTL_SECONDS).contains(&ttl)
        {
            return Err(SeError::invalid(
                "ttl_seconds",
                "expected 1..=86400 seconds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DelegateStartOutput {
    pub agent_id: AgentId,
    pub name: String,
    pub session_id: SessionId,
    pub provider: Provider,
    pub model: Option<String>,
    pub profile: String,
    pub ttl_seconds: u32,
    pub handoff_included: bool,
}

#[derive(Clone)]
pub struct DelegateStartPlan {
    pub project: Named<ProjectId>,
    pub owner: se_types::HumanId,
    pub creator: Actor,
    pub cwd: NativePath,
    pub agent_id: AgentId,
    pub name: String,
    pub role: String,
    pub provider: Provider,
    pub stored_provider: se_store::Provider,
    pub harness: Option<String>,
    pub model: Option<String>,
    pub named_profile: String,
    pub permission: PermissionProfile,
    pub ephemeral: EphemeralSpec,
    pub max_active_per_parent: u32,
    pub composed_task: String,
    pub handoff_included: bool,
    pub idempotency_key: IdempotencyKey,
    pub normalized_intent: serde_json::Value,
    pub existing_agent: Option<(AgentId, String)>,
    /// Set only by remote delegation, after destination admission.
    pub remote: Option<RemoteDelegation>,
}

/// The authenticated caller and the approved agent whose consent admits a
/// remote worker. Never supplied by a local operation DTO.
#[derive(Clone)]
pub struct RemoteDelegation {
    pub anchor: se_types::remote::RemoteTarget,
    pub attribution: se_types::remote::RemoteAttribution,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegateCancel {
    /// Temporary agent ID or name to stop and terminally retire.
    pub agent: String,
    pub idempotency_key: IdempotencyKey,
}

impl Validate for DelegateCancel {
    fn validate(&self) -> Result<()> {
        bounded("agent", &self.agent, 128, false)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DelegateCancelOutput {
    pub agent_id: AgentId,
    pub name: String,
    pub retired: bool,
    pub stopped_lifecycle: bool,
}

#[derive(Clone)]
pub struct DelegateCancelPlan {
    pub project: ProjectId,
    pub agent: Named<AgentId>,
    pub already_retired: bool,
    pub final_session: Option<SessionId>,
    pub idempotency_key: IdempotencyKey,
}

pub fn step_start<R: Snapshot>(
    kernel: &Kernel,
    input: DelegateStart,
    configuration: Option<&ConfigFile>,
    cx: &mut Cx<'_, R>,
) -> Result<OpStep<AnyOutput, Then, CustodyPlan>> {
    Ok(OpStep::Custody(CustodyPlan::DelegateStart(Box::new(
        plan_start(kernel, input, configuration, cx)?,
    ))))
}

pub fn step_cancel<R: Snapshot>(
    input: DelegateCancel,
    cx: &mut Cx<'_, R>,
) -> Result<OpStep<AnyOutput, Then, CustodyPlan>> {
    Ok(OpStep::Custody(CustodyPlan::DelegateCancel(plan_cancel(
        input, cx,
    )?)))
}
