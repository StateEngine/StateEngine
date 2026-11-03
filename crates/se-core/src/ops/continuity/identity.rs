use super::types::*;
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, EventBody, Snapshot};
use se_types::{AgentId, Read, Result, SeError};

pub(super) struct Identity {
    pub principal: ContinuityPrincipal,
    pub role: Option<String>,
    pub harness: String,
    pub model: Option<String>,
    pub conversation: Option<String>,
}
pub(super) fn resolve<R: Snapshot>(
    preview: Option<&AgentId>,
    cx: &mut Cx<'_, R>,
) -> Result<Identity> {
    let project = crate::ops::receipt::named_project(cx)?;
    let (agent, session, is_preview) = match (&cx.admission.actor, preview, &cx.admission.session) {
        (Actor::Agent(agent), None, Some(session)) => (agent.clone(), Some(session.clone()), false),
        (Actor::Human(_), Some(agent), None) => (agent.clone(), None, true),
        (Actor::Agent(_), Some(_), _) => {
            return Err(SeError::new(se_types::Detail::OwnerRequired(
                se_types::details::OwnerRequired {
                    op: "continuity preview".into(),
                },
            )));
        }
        _ => {
            return Err(SeError::invalid(
                "continuity authority",
                "a bound session, or owner CLI --preview AGENT without a session",
            ));
        }
    };
    let principal = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|e| store_error(&e))?,
        "continuity agent",
        "Select a registered agent in this admitted project.",
    )?;
    let (name, role) = match &principal.current.body {
        EventBody::PrincipalRegistered { name, role, .. } => {
            (name.clone(), (!role.is_empty()).then(|| role.clone()))
        }
        EventBody::PrincipalRenamed { name, .. } => (
            name.clone(),
            principal.original.as_deref().and_then(|e| match &e.body {
                EventBody::PrincipalRegistered { role, .. } if !role.is_empty() => {
                    Some(role.clone())
                }
                _ => None,
            }),
        ),
        _ => {
            return Err(scope::unreadable(
                "continuity identity",
                "agent registration has an invalid current head",
            ));
        }
    };
    // The provider/model of a bound session comes from its saved session and
    // verified harness binding, never an unrelated owner's profile event.
    let profile = if is_preview {
        let saved = scope::require_present(
            cx.read
                .profile(agent.clone())
                .map_err(|e| store_error(&e))?,
            "continuity profile",
            "Restore the saved provider profile before previewing context.",
        )?;
        let EventBody::ProfileSaved { profile, .. } = saved.current.body else {
            return Err(scope::unreadable(
                "continuity profile",
                "current profile is not a saved profile",
            ));
        };
        Some(profile)
    } else {
        None
    };
    let record = match &session {
        Some(id) => cx.read.session(id.clone()),
        None => cx.read.latest_session(agent.clone()),
    }
    .map_err(|e| store_error(&e))?;
    let (provider, conversation, saved_session) = match record {
        Read::Absent { .. } if is_preview => (
            profile
                .as_ref()
                .ok_or_else(|| scope::unreadable("preview profile", "no saved provider"))?
                .provider,
            None,
            None,
        ),
        other => {
            let saved = scope::require_present(
                other,
                "continuity session",
                "Use the active session binding; owner preview may inspect an agent without binding it.",
            )?;
            let first = saved.original.as_deref().unwrap_or(&saved.current);
            let EventBody::SessionPrepared {
                session: prepared,
                agent: target,
                provider,
                native_ref,
                generation,
                ..
            } = &first.body
            else {
                return Err(scope::unreadable(
                    "continuity session",
                    "original preparation is unavailable",
                ));
            };
            if target != &agent {
                return Err(scope::unreadable(
                    "continuity session",
                    "preparation names another agent",
                ));
            }
            if let Some(id) = &session
                && (id != prepared
                    || *generation != cx.admission.generation
                    || !matches!(&saved.current.body, EventBody::SessionActivated {session: active, ..} if active==id))
            {
                return Err(SeError::invalid(
                    "continuity session",
                    "the exact active session and current admitted generation; ended, prepared, revoked and superseded bindings cannot resume context",
                ));
            }
            (*provider, Some(native_ref.clone()), Some(prepared.clone()))
        }
    };
    let harness = match provider {
        se_store::Provider::Claude => "claude",
        se_store::Provider::Codex => "codex",
        se_store::Provider::SeCode => "secode",
    }
    .into();
    Ok(Identity {
        principal: ContinuityPrincipal {
            project,
            agent: se_types::Named { id: agent, name },
            session_id: saved_session,
            preview: is_preview,
        },
        role,
        harness,
        model: profile.and_then(|profile| profile.model),
        conversation,
    })
}
