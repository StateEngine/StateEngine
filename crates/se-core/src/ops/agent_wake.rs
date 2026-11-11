//! Explicit wake selection for one running agent. Wake offers the target's
//! pending mail and reports the committed offer; it never launches a process
//! and never claims the mail was read or acted on.
use super::{inputs::Validate, process_plan};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{EventBody, Snapshot};
use se_types::{AgentId, LifecycleId, Named, ProjectId, Result, SeError, SessionId};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWake {
    pub target_agent_id: Option<AgentId>,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<String>,
}
impl Validate for AgentWake {
    fn validate(&self) -> Result<()> {
        if let Some(value) = &self.owner_agent {
            super::inputs::bounded("agent selector", value, 512, false)?;
        }
        Ok(())
    }
}
/// Pure selection: the admitted project plus one exact agent this actor may
/// control. The host decides what is live and what the offer window proves.
#[derive(Clone, Debug)]
pub struct WakePlan {
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WakeOutcome {
    /// A new mail offer was committed for the target during the wait window.
    Offered,
    /// Reserved: stream writes are offers. Only pinned, committed user input
    /// proves delivery, and wake never constructs this variant.
    Delivered,
    /// The window closed without a new committed offer; the mail stays queued.
    Pending,
    /// No wake could run: the target is absent or has no live process here.
    Refused,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WakeLifecycle {
    /// "running" while a live job owned the window; "not_running" after one
    /// settled inside it or none existed.
    pub state: String,
    pub session: Option<SessionId>,
    pub lifecycle: Option<LifecycleId>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WakeOffer {
    /// transport-written, vendor-reported, native-admitted or committed-event.
    pub kind: String,
    pub transport: Option<String>,
    pub bytes: Option<u64>,
    pub observed_at_us: Option<i64>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WakeResult {
    pub outcome: WakeOutcome,
    pub agent: Named<AgentId>,
    pub lifecycle: WakeLifecycle,
    /// Present only for Offered; the committed offer facts, never mail counts.
    pub offer: Option<WakeOffer>,
    pub detail: Option<String>,
    pub remedy: Option<String>,
}
pub fn plan<R: Snapshot>(input: AgentWake, cx: &mut Cx<'_, R>) -> Result<WakePlan> {
    input.validate()?;
    if input.target_agent_id.is_none() && input.owner_agent.is_none() {
        return Err(SeError::invalid(
            "agent selector",
            "one exact agent ID or CLI name; wake never selects the calling agent",
        ));
    }
    let id = match &cx.admission.scope {
        se_store::Scope::Project(id) => id.clone(),
        _ => {
            return Err(scope::unreadable(
                "wake project",
                "the admitted project scope",
            ));
        }
    };
    let project = scope::require_present(
        cx.read.project(id.clone()).map_err(|e| store_error(&e))?,
        "wake project",
        "Select an initialized project.",
    )?;
    let project = project_name(&project.current.body)?;
    let agent = process_plan::target(
        input.target_agent_id.as_ref(),
        input.owner_agent.as_deref(),
        cx,
    )?;
    let control = scope::require_present(
        cx.read
            .control_target(agent.clone())
            .map_err(|e| store_error(&e))?,
        "wake target",
        "Choose your own agent or a direct child you are currently allowed to control.",
    )?;
    let name = match &control.principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name.clone()
        }
        _ => return Err(scope::unreadable("wake target", "wrong principal metadata")),
    };
    Ok(WakePlan {
        project,
        agent: Named { id: agent, name },
    })
}
fn project_name(body: &EventBody<se_store::StoredText>) -> Result<Named<ProjectId>> {
    match body {
        EventBody::ProjectRegistered { project, name, .. }
        | EventBody::ProjectUpdated { project, name, .. }
        | EventBody::ProjectMoved { project, name, .. } => Ok(Named {
            id: project.clone(),
            name: name.clone(),
        }),
        _ => Err(scope::unreadable(
            "wake project",
            "non-active project metadata",
        )),
    }
}
