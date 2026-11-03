//! Owner removal input and achieved-effect receipts. History and user/provider
//! work are preserved; unresolved processes or changed integrations stay named.
use super::{ProcessView, agent_stop::AgentStopResult, inputs::Validate};
use schemars::JsonSchema;
use se_types::{
    AgentId, EventId, IdempotencyKey, LifecycleId, Named, ProjectId, Result, SessionId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRemove {
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub keep_integrations: bool,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for ProjectRemove {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovedAgent {
    pub agent: Named<AgentId>,
    pub prior_state: String,
    pub witness: RemovalWitness,
    pub process: Option<ProcessView>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovedProcess {
    pub lifecycle_id: LifecycleId,
    pub process: ProcessView,
    pub witness: RemovalWitness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RevokedCredential {
    pub credential_id: String,
    pub kind: String,
    pub session_id: Option<SessionId>,
    pub state: String,
    pub at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovalWitness {
    pub state: String,
    pub method: Option<String>,
    pub observed_at: Option<String>,
    pub detail: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovedIntegration {
    pub path: String,
    pub entry: String,
    pub action: String,
    pub witness: RemovalWitness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovedItem {
    pub what: String,
    pub path: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct KeptItem {
    pub what: String,
    pub path: Option<String>,
    pub note: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovalObligation {
    pub what: String,
    pub reason: String,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovedProject {
    pub id: ProjectId,
    pub name: String,
    pub root: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProjectRemoval {
    pub project: RemovedProject,
    pub outcome: String,
    pub removed_at: Option<String>,
    pub event_id: Option<EventId>,
    pub agents_stopped: Vec<RemovedAgent>,
    pub processes_stopped: Vec<RemovedProcess>,
    pub processes_may_remain: Vec<AgentStopResult>,
    pub credentials_revoked: Vec<RevokedCredential>,
    pub integrations: Vec<RemovedIntegration>,
    pub removed: Vec<RemovedItem>,
    pub kept: Vec<KeptItem>,
    pub remaining: Vec<RemovalObligation>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovedRuntime {
    pub action: String,
    pub process: Option<ProcessView>,
    pub witness: RemovalWitness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovedMachineCredential {
    pub state: String,
    pub witness: RemovalWitness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovalNext {
    pub text: String,
    pub command: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemoveResult {
    pub idempotency_key: IdempotencyKey,
    pub scope: String,
    pub outcome: String,
    pub projects: Vec<ProjectRemoval>,
    pub runtime: RemovedRuntime,
    pub machine_credential: RemovedMachineCredential,
    pub next: RemovalNext,
}

/// Selected registered projects only. Each project is re-read in its own
/// admitted snapshot before stopping processes or preparing a tombstone.
#[derive(Clone)]
pub struct RemovePlan {
    pub input: ProjectRemove,
    pub projects: Vec<Named<ProjectId>>,
}
pub fn plan<R: se_store::Snapshot>(
    input: ProjectRemove,
    cx: &mut crate::commit::Cx<'_, R>,
) -> Result<RemovePlan> {
    input.validate()?;
    if !input.all && !matches!(cx.admission.scope, se_store::Scope::Project(_)) {
        return Err(se_types::SeError::invalid(
            "remove project",
            "one selected project or --all",
        ));
    }
    Ok(RemovePlan {
        input,
        projects: super::stop_plan::projects(cx)?,
    })
}
