use super::types::*;
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, EventBody, Snapshot, WriterModeValue};
use se_types::{AgentId, Read, Result, SeError};

pub(super) struct Identity {
    pub command_home: Option<std::path::PathBuf>,
    pub principal: ContinuityPrincipal,
    pub role: Option<String>,
    pub harness: String,
    pub model: Option<String>,
    pub conversation: Option<String>,
}
pub(super) struct HandoffIdentity {
    pub project: se_types::Named<se_types::ProjectId>,
    pub agent: se_types::Named<AgentId>,
    pub session_id: Option<se_types::SessionId>,
}

pub(super) fn resolve_handoff<R: Snapshot>(
    from: Option<&str>,
    cx: &mut Cx<'_, R>,
) -> Result<HandoffIdentity> {
    let project = crate::ops::receipt::named_project(cx)?;
    let selected = match from {
        Some(selector) => {
            let Actor::Agent(agent) = scope::selected_actor(cx, selector)? else {
                return Err(SeError::invalid("from", "a project agent, not the owner"));
            };
            Some(agent)
        }
        None => None,
    };
    let agent = match (&cx.admission.actor, selected.as_ref()) {
        (Actor::Human(_), None) => {
            let mut error = SeError::new(se_types::Detail::UsageMissingArgument(
                se_types::details::UsageMissingArgument {
                    command: "se handoff export".into(),
                    argument: "--from AGENT".into(),
                },
            ));
            error.body = error.body.with_remedy(se_types::Remedy {
                text: "Choose a project agent with the command below, then pass --from AGENT to export its handoff packet.".into(),
                command: Some(se_types::Cmd::Se {
                    argv: se_types::Argv::from_op(&OwnerResumeChoices(&project.id))?,
                }),
            });
            return Err(error);
        }
        _ => scope::working_agent(cx.admission, selected.as_ref(), "handoff.export")?,
    };
    let principal = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|e| store_error(&e))?,
        "handoff agent",
        "Select a registered agent in this admitted project.",
    )?;
    let (name, _role) = principal_name_role(&principal)?;
    let session_id = match (&cx.admission.actor, &cx.admission.session) {
        (Actor::Agent(caller), Some(bound)) if caller == &agent => Some(bound.clone()),
        _ => match cx
            .read
            .latest_session(agent.clone())
            .map_err(|e| store_error(&e))?
        {
            Read::Present { value } => {
                let first = value.original.as_deref().unwrap_or(&value.current);
                match &first.body {
                    EventBody::SessionPrepared { session, .. } => Some(session.clone()),
                    _ => None,
                }
            }
            Read::Absent { .. } => None,
            other => {
                scope::require_present(
                    other,
                    "handoff session",
                    "Restore the agent's latest session record before retrying.",
                )?;
                None
            }
        },
    };
    Ok(HandoffIdentity {
        project,
        agent: se_types::Named { id: agent, name },
        session_id,
    })
}

pub(super) fn resolve<R: Snapshot>(
    preview: Option<&AgentId>,
    cx: &mut Cx<'_, R>,
) -> Result<Identity> {
    let project = crate::ops::receipt::named_project(cx)?;
    let (agent, session, is_preview) = admit(preview, cx, &project)?;
    let principal = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|e| store_error(&e))?,
        "continuity agent",
        "Select a registered agent in this admitted project.",
    )?;
    let (name, role) = principal_name_role(&principal)?;
    let profile = if is_preview {
        preview_profile(&agent, cx)?
    } else {
        None
    };
    let (provider, conversation, saved_session) =
        session_binding(&agent, &session, is_preview, &profile, cx)?;
    let harness = match provider {
        se_store::Provider::Claude => "claude",
        se_store::Provider::Codex => "codex",
        se_store::Provider::SeCode => "secode",
        se_store::Provider::Acp => "acp",
    }
    .into();
    Ok(Identity {
        command_home: None,
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

fn admit<R: Snapshot>(
    preview: Option<&AgentId>,
    cx: &mut Cx<'_, R>,
    project: &se_types::Named<se_types::ProjectId>,
) -> Result<(AgentId, Option<se_types::SessionId>, bool)> {
    match (&cx.admission.actor, preview, &cx.admission.session) {
        (Actor::Agent(agent), None, Some(session)) => {
            Ok((agent.clone(), Some(session.clone()), false))
        }
        (Actor::Human(_), Some(agent), None) => Ok((agent.clone(), None, true)),
        (Actor::Human(_), None, None) => {
            let mut error = SeError::new(se_types::Detail::UsageMissingArgument(
                se_types::details::UsageMissingArgument {
                    command: "se resume".into(),
                    argument: "--preview AGENT".into(),
                },
            ));
            error.body = error.body.with_remedy(se_types::Remedy {
                text: "Choose a saved agent with the command below, then use se resume --preview AGENT to inspect its context. Context inspection does not restart a provider conversation.".into(),
                command: Some(se_types::Cmd::Se {
                    argv: se_types::Argv::from_op(&OwnerResumeChoices(&project.id))?,
                }),
            });
            Err(error)
        }
        (Actor::Agent(_), Some(_), _) => Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "continuity preview".into(),
            },
        ))),
        _ => Err(SeError::invalid(
            "continuity authority",
            "a bound session, or owner CLI --preview AGENT without a session",
        )),
    }
}

fn principal_name_role(principal: &se_store::ProjectionRecord) -> Result<(String, Option<String>)> {
    match &principal.current.body {
        EventBody::PrincipalRegistered { name, role, .. } => {
            Ok((name.clone(), (!role.is_empty()).then(|| role.clone())))
        }
        EventBody::PrincipalRenamed { name, .. } => Ok((
            name.clone(),
            principal.original.as_deref().and_then(|e| match &e.body {
                EventBody::PrincipalRegistered { role, .. } if !role.is_empty() => {
                    Some(role.clone())
                }
                _ => None,
            }),
        )),
        _ => Err(scope::unreadable(
            "continuity identity",
            "agent registration has an invalid current head",
        )),
    }
}

fn preview_profile<R: Snapshot>(
    agent: &AgentId,
    cx: &mut Cx<'_, R>,
) -> Result<Option<se_store::Profile>> {
    // The provider/model of a bound session comes from its saved session and
    // verified harness binding, never an unrelated owner's profile event.
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
    Ok(Some(profile))
}

fn session_binding<R: Snapshot>(
    agent: &AgentId,
    session: &Option<se_types::SessionId>,
    is_preview: bool,
    profile: &Option<se_store::Profile>,
    cx: &mut Cx<'_, R>,
) -> Result<(
    se_store::Provider,
    Option<String>,
    Option<se_types::SessionId>,
)> {
    let record = match session {
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
                generation,
                ..
            } = &first.body
            else {
                return Err(scope::unreadable(
                    "continuity session",
                    "original preparation is unavailable",
                ));
            };
            if target != agent {
                return Err(scope::unreadable(
                    "continuity session",
                    "preparation names another agent",
                ));
            }
            if let Some(id) = session
                && (id != prepared
                    || (*generation != cx.admission.generation
                        && !(*generation < cx.admission.generation
                            && reconciled(&saved, agent, id, cx)?))
                    || !matches!(&saved.current.body, EventBody::SessionActivated {session: active, ..} if active==id))
            {
                return Err(SeError::invalid(
                    "continuity session",
                    "the exact active session in its launch generation or with current-host native reconciliation; ended, prepared, revoked, superseded and unproved bindings cannot resume context",
                ));
            }
            let reference = match super::super::session_reference::read(cx.read, &saved)? {
                Read::Present { value } => Some(value.as_str().to_owned()),
                Read::Absent { .. } => None,
                other => Some(
                    scope::require_present(
                        other,
                        "continuity provider reference",
                        "Restore its original actual provider binding.",
                    )?
                    .as_str()
                    .to_owned(),
                ),
            };
            (*provider, reference, Some(prepared.clone()))
        }
    };
    Ok((provider, conversation, saved_session))
}

fn reconciled<R: Snapshot>(
    session: &se_store::ProjectionRecord,
    agent: &AgentId,
    id: &se_types::SessionId,
    cx: &mut Cx<'_, R>,
) -> Result<bool> {
    let EventBody::SessionActivated {
        process: Some(process),
        ..
    } = &session.current.body
    else {
        return Ok(false);
    };
    let process = match cx
        .read
        .process(process.clone())
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => value,
        Read::Absent { .. } => return Ok(false),
        other => scope::require_present(
            other,
            "continuity recovered process",
            "Restore its original current-host reconciliation before resuming context.",
        )?,
    };
    Ok(process.current.header.scope == session.current.header.scope
        && process.current.writer.kind()
            == (se_store::WriterKind::Host {
                generation: cx.admission.generation,
            })
        && process.current.durability == se_store::CommitDurability::Full
        && matches!(&process.current.body,
            EventBody::ProcessTransition { identity, to: se_store::ProcessState::Running, .. }
                if identity.session.as_ref() == Some(id)
                    && identity.principal == Actor::Agent(agent.clone())))
}

struct OwnerResumeChoices<'a>(&'a se_types::ProjectId);
impl se_types::OperationCommand for OwnerResumeChoices<'_> {
    fn cli_argv(&self) -> Vec<String> {
        vec![
            "se".into(),
            "--project".into(),
            self.0.to_string(),
            "agent".into(),
            "list".into(),
        ]
    }
}
