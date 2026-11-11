//! Verified session-bound identity: the admitted principal, its authority scope
//! and the session binding state. No credential material is ever returned.
use crate::commit::Cx;
use crate::dispatch::admitted;
use crate::ops::inputs::Validate;
use crate::scope;
use crate::store_error::store_error;
use schemars::JsonSchema;
use se_store::{Actor, EventBody, GrantKey, Snapshot};
use se_types::{AgentId, ProjectId, Read, Result, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityWhoami;

impl Validate for IdentityWhoami {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalProject {
    pub id: ProjectId,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalAgent {
    pub id: AgentId,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalSession {
    pub id: SessionId,
    /// Surface recorded by the original session preparation; absent when that
    /// preparation retains no surface or is not retained at all.
    pub source: Read<String>,
    /// Host writer generation that admitted this request.
    pub generation: u64,
}

/// The admitted authority scope and the observed session binding state.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalBinding {
    /// Observed current session projection state.
    pub state: String,
    pub scope: String,
    pub auth: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalOutput {
    pub project: PrincipalProject,
    pub agent: PrincipalAgent,
    pub session: PrincipalSession,
    /// Active creator-control grant keys this session currently holds.
    pub grants: Vec<String>,
    pub binding: PrincipalBinding,
}

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn whoami<R: Snapshot>(_input: IdentityWhoami, cx: &mut Cx<'_, R>) -> Result<PrincipalOutput> {
    admitted(cx)?;
    let project_id = scope::project(cx.admission)?;
    let (agent, session) = match (&cx.admission.actor, &cx.admission.session) {
        (Actor::Agent(agent), Some(session)) => (agent.clone(), session.clone()),
        _ => {
            return Err(scope::unreadable(
                "identity.whoami",
                "session authority admits no agent with a bound session",
            ));
        }
    };

    let project = scope::require_present(
        cx.read
            .project(project_id.clone())
            .map_err(|e| store_error(&e))?,
        "identity project",
        "Reconnect to the project that admitted this session; its registration is not retained in this snapshot.",
    )?;
    let project_name = match &project.current.body {
        EventBody::ProjectRegistered { name, .. }
        | EventBody::ProjectUpdated { name, .. }
        | EventBody::ProjectMoved { name, .. } => name.clone(),
        _ => {
            return Err(scope::unreadable(
                "identity project",
                "the admitted project projection is not a registration, update or move",
            ));
        }
    };

    let principal = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|e| store_error(&e))?,
        "identity agent",
        "Reconnect to the project that registered this agent; its principal is not retained in this snapshot.",
    )?;
    let agent_name = match &principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name.clone()
        }
        _ => {
            return Err(scope::unreadable(
                "identity agent",
                "the admitted agent projection is not a principal registration",
            ));
        }
    };

    let session_record = scope::require_present(
        cx.read
            .session(session.clone())
            .map_err(|e| store_error(&e))?,
        "identity session",
        "Reconnect with a launched session credential; the admitted session is not retained in this snapshot.",
    )?;
    let binding_state = match &session_record.current.body {
        EventBody::SessionPrepared { .. } => "prepared",
        EventBody::SessionActivated { .. } => "activated",
        EventBody::SessionEnded { .. } => "ended",
        EventBody::SessionRevoked { .. } => "revoked",
        _ => {
            return Err(scope::unreadable(
                "identity session",
                "the admitted session projection is not a session state",
            ));
        }
    };
    let source = match session_record.original.as_deref() {
        Some(original) => match &original.body {
            EventBody::SessionPrepared {
                surface: Some(surface),
                ..
            } => Read::Present {
                value: surface.as_str().to_string(),
            },
            EventBody::SessionPrepared { .. } => Read::Absent {
                checked: "the original session preparation records no surface".into(),
            },
            _ => Read::Absent {
                checked: "the original session projection is not a preparation".into(),
            },
        },
        None => Read::Absent {
            checked: "the original session preparation is not retained".into(),
        },
    };

    let grants = match cx
        .read
        .grant(
            Actor::Agent(agent.clone()),
            GrantKey::AgentCanCreate(agent.clone()),
        )
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => {
            if matches!(
                value.current.body,
                EventBody::GrantRecorded { active: true, .. }
            ) {
                vec![format!("agent.{agent}.can-create")]
            } else {
                Vec::new()
            }
        }
        Read::Absent { .. } => Vec::new(),
        Read::Unreadable {
            source: unreadable_source,
            reason,
            ..
        } => return Err(scope::unreadable(&unreadable_source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("identity grants", &what)),
    };

    Ok(PrincipalOutput {
        project: PrincipalProject {
            id: project_id,
            name: project_name,
        },
        agent: PrincipalAgent {
            id: agent,
            name: agent_name,
        },
        session: PrincipalSession {
            id: session,
            source,
            generation: cx.admission.generation,
        },
        grants,
        binding: PrincipalBinding {
            state: binding_state.into(),
            scope: "project".into(),
            auth: "session".into(),
        },
    })
}
