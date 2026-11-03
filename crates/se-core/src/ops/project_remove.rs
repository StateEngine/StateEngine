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
/// A tombstone keeps its original registration for read-only status and retry
/// receipts. No filesystem existence or active-root lookup can replace it.
pub fn removed_view(head: &se_store::ProjectionRecord) -> Result<Option<super::RemovalView>> {
    let se_store::EventBody::ProjectRemoved { project, .. } = &head.current.body else {
        return Ok(None);
    };
    let original = head.original.as_deref().ok_or_else(|| {
        crate::scope::unreadable(
            "removed project",
            "its original registration is unavailable",
        )
    })?;
    let (registered, name, roots) = match &original.body {
        se_store::EventBody::ProjectRegistered {
            project,
            name,
            roots,
            ..
        }
        | se_store::EventBody::ProjectUpdated {
            project,
            name,
            roots,
            ..
        } => (project, name, roots),
        _ => {
            return Err(crate::scope::unreadable(
                "removed project",
                "its retained metadata is not a registration",
            ));
        }
    };
    if registered != project {
        return Err(crate::scope::unreadable(
            "removed project",
            "registration and tombstone identities differ",
        ));
    }
    let root = roots.first().ok_or_else(|| {
        crate::scope::unreadable("removed project", "its registered root is unavailable")
    })?;
    Ok(Some(super::RemovalView {
        project: Named {
            id: project.clone(),
            name: name.clone(),
        },
        root: root.path.to_local()?.display().to_string(),
        removed_at: super::receipt::timestamp(head.current.recorded_at_us)?,
        event_id: head.current.header.event.clone(),
    }))
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
    if !input.all
        && let se_store::Scope::Project(project) = &cx.admission.scope
    {
        let head = crate::scope::require_present(
            cx.read
                .project(project.clone())
                .map_err(|e| crate::store_error::store_error(&e))?,
            "removal project",
            "Select the retained project by its exact ID.",
        )?;
        if matches!(
            head.current.body,
            se_store::EventBody::ProjectRemoved { .. }
        ) {
            let original = head.original.as_deref().ok_or_else(|| {
                crate::scope::unreadable(
                    "removal owner",
                    "the original registration is unavailable",
                )
            })?;
            if !matches!(&original.body, se_store::EventBody::ProjectRegistered { owner, .. } if cx.admission.actor == se_store::Actor::Human(owner.clone()))
            {
                return Err(se_types::SeError::new(se_types::Detail::OwnerRequired(
                    se_types::details::OwnerRequired {
                        op: "project.remove".into(),
                    },
                )));
            }
            return Ok(RemovePlan {
                input,
                projects: vec![],
            });
        }
    }
    Ok(RemovePlan {
        input,
        projects: super::stop_plan::projects(cx)?,
    })
}
