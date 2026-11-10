//! Saved identity readback. Native lifecycle and provider conversation facts are
//! deliberately unknown until the runtime observation adapter supplies them.
use super::{AgentRow, AgentShow, AgentStatusOutput};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, EventBody, Snapshot};
use se_types::{Read, Result};

/// Saved agents in this finite principal page. Native lifecycle facts remain
/// explicitly unknown; reading this page never starts or resumes a process.
pub fn page<R: Snapshot>(
    budget: se_store::ReadBudget,
    cx: &mut Cx<'_, R>,
) -> Result<se_types::Page<AgentRow>> {
    let principals = cx.read.principals(budget).map_err(|e| store_error(&e))?;
    let mut fields = principals.window().fields().cloned().ok_or_else(|| {
        scope::unreadable(
            "agent status page",
            "store window accounting is unavailable",
        )
    })?;
    let next = principals.next().cloned();
    let mut rows = Vec::new();
    for record in principals.into_items() {
        let agent = match record.current.body {
            EventBody::PrincipalRegistered {
                principal: Actor::Agent(agent),
                ..
            }
            | EventBody::PrincipalRenamed {
                principal: Actor::Agent(agent),
                ..
            } => agent,
            _ => continue,
        };
        if matches!(&cx.admission.actor,Actor::Agent(bound) if bound!=&agent) {
            continue;
        }
        let row = scope::require_present(
            show(
                AgentShow {
                    target_agent_id: Some(agent.clone()),
                },
                cx,
            )?
            .agent,
            "saved agent page row",
            "Read the saved agent by its exact ID in this project, then refresh the agent list.",
        )?;
        rows.push(row);
    }
    fields.returned = rows.len() as u64;
    fields.bytes = serde_json::to_vec(&rows)
        .map_err(|e| scope::unreadable("agent status page encoding", &e.to_string()))?
        .len() as u64;
    if fields.bytes > u64::from(fields.max_bytes.get()) {
        return Err(scope::unreadable(
            "agent status page",
            "expanded saved rows exceed the finite response byte budget",
        ));
    }
    // Principal omissions cannot be relabelled as an exact count of agents.
    if next.is_some() {
        fields.omitted_after = se_types::Omission::Unknown {
            reason: se_types::OmissionReason::Limit,
        };
    }
    se_types::Page::new(rows, se_types::Window::new(fields)?, next)
}

pub fn show<R: Snapshot>(input: AgentShow, cx: &mut Cx<'_, R>) -> Result<AgentStatusOutput> {
    let agent = scope::working_agent(cx.admission, input.target_agent_id.as_ref(), "agent.show")?;
    // An owner's saved profile and rename events are not session history.
    // The target-bound control port exposes this agent's metadata without
    // granting its session visibility into the owner's other events.
    let mut controlled_profile = None;
    let principal = if matches!(&cx.admission.actor, Actor::Agent(_)) {
        match cx
            .read
            .control_target(agent.clone())
            .map_err(|error| store_error(&error))?
        {
            Read::Present { value } => {
                controlled_profile = Some(value.profile);
                Read::Present {
                    value: value.principal,
                }
            }
            other => other.map(|target| target.principal),
        }
    } else {
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|error| store_error(&error))?
    };
    let principal = match principal {
        Read::Present { value } => value,
        Read::Absent { checked } => {
            return Ok(AgentStatusOutput {
                agent: Read::Absent { checked },
            });
        }
        Read::Unknown { what } => {
            return Ok(AgentStatusOutput {
                agent: Read::Unknown { what },
            });
        }
        Read::Unreadable {
            source,
            reason,
            error,
        } => {
            return Ok(AgentStatusOutput {
                agent: Read::Unreadable {
                    source,
                    reason,
                    error,
                },
            });
        }
    };
    let (name, role) = match principal.current.body {
        EventBody::PrincipalRegistered { name, role, .. } => {
            (name, (!role.is_empty()).then_some(role))
        }
        EventBody::PrincipalRenamed { name, .. } => {
            let role = principal
                .original
                .as_deref()
                .and_then(|original| match &original.body {
                    EventBody::PrincipalRegistered { role, .. } if !role.is_empty() => {
                        Some(role.clone())
                    }
                    _ => None,
                });
            (name, role)
        }
        _ => {
            return Err(scope::unreadable(
                "saved agent identity",
                "current registration/name unavailable",
            ));
        }
    };
    let profile = match controlled_profile {
        Some(profile) => profile,
        None => cx
            .read
            .profile(agent.clone())
            .map_err(|error| store_error(&error))?,
    };
    let saved = match profile {
        Read::Present { value } => value,
        Read::Absent { checked } => {
            return Ok(AgentStatusOutput {
                agent: Read::Unknown {
                    what: format!("saved agent exists but its profile is absent: {checked}"),
                },
            });
        }
        Read::Unknown { what } => {
            return Ok(AgentStatusOutput {
                agent: Read::Unknown { what },
            });
        }
        Read::Unreadable {
            source,
            reason,
            error,
        } => {
            return Ok(AgentStatusOutput {
                agent: Read::Unreadable {
                    source,
                    reason,
                    error,
                },
            });
        }
    };
    let EventBody::ProfileSaved { profile, .. } = saved.current.body else {
        return Err(scope::unreadable(
            "saved agent profile",
            "current immutable profile unavailable",
        ));
    };
    let provider = match profile.provider {
        se_store::Provider::Claude => se_types::Provider::Claude,
        se_store::Provider::Codex => se_types::Provider::Codex,
        se_store::Provider::SeCode => se_types::Provider::SeCode,
        se_store::Provider::Acp => se_types::Provider::Acp,
    };
    let (session, conversation, mut resume) = super::agent_session::read(&agent, cx)?;
    if provider == se_types::Provider::SeCode {
        resume.ready = false;
        resume.mode = "compatible-service-required".into();
        resume.reason = Some(super::AgentCommand::SECODE_RESUME_UNAVAILABLE.into());
        resume.command = None;
        resume.argv = None;
    }
    let secode_binding = if provider == se_types::Provider::SeCode {
        Some(retained_secode_binding(session.session_id.as_ref(), cx)?)
    } else {
        None
    };
    let secode_runtime = secode_binding.as_ref().map(|binding| match binding {
        Read::Absent { checked } if session.session_id.is_none() => Read::Absent {
            checked: checked.clone(),
        },
        Read::Unknown { what } => Read::Unknown { what: what.clone() },
        Read::Unreadable { source, reason, error } => Read::Unreadable {
            source: source.clone(),
            reason: reason.clone(),
            error: error.clone(),
        },
        _ => Read::Unknown {
            what: "Current service and execution observations require the owning runtime; retained custody is shown separately.".into(),
        },
    });
    let unread = cx
        .read
        .message_count(se_store::MessageQuery {
            recipient: Some(Actor::Agent(agent.clone())),
            sender: None,
            kind: None,
            unread_only: true,
            full_body: false,
        })
        .map_err(|error| store_error(&error))?;
    Ok(AgentStatusOutput {
        agent: Read::Present {
            value: AgentRow {
                provider_activity: matches!(provider, se_types::Provider::Claude | se_types::Provider::Codex).then(|| Read::Unknown {
                    what: "Provider turn activity requires the owning runtime; native liveness does not prove a reply. Check provider sign-in and saved history before resubmitting input.".into(),
                }),
                acp_runtime: (provider == se_types::Provider::Acp).then(|| Read::Unknown {
                    what: "The native protocol connection has not been observed".into(),
                }),
                harness_policy_notice: (provider == se_types::Provider::Acp)
                    .then(|| se_types::ACP_NO_SANDBOX_NOTICE.into()),
                secode_binding,
                secode_runtime,
                id: agent,
                name,
                role,
                provider,
                model: profile.model,
                profile: profile.named_profile,
                session,
                conversation,
                resume,
                unread: Some(unread),
                last_activity_at: None,
            },
        },
    })
}

fn retained_secode_binding<R: Snapshot>(
    session: Option<&se_types::SessionId>,
    cx: &mut Cx<'_, R>,
) -> Result<Read<super::SecodeBindingView>> {
    let Some(session) = session else {
        return Ok(Read::Absent {
            checked: "this agent has no saved session".into(),
        });
    };
    let source = super::process_commit::session_credential_id(session, "capture-source")?;
    let record = match cx
        .read
        .capture_source(source)
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => value,
        Read::Absent { checked } => return Ok(Read::Absent { checked }),
        Read::Unreadable {
            source,
            reason,
            error,
        } => {
            return Ok(Read::Unreadable {
                source,
                reason,
                error,
            });
        }
        Read::Unknown { what } => return Ok(Read::Unknown { what }),
    };
    let EventBody::CaptureSource {
        session: found,
        native_ref,
        incarnation,
        ..
    } = &record.original.as_deref().unwrap_or(&record.current).body
    else {
        return Ok(Read::Unreadable {
            source: "retained SE Code binding".into(),
            reason: "the source has no original binding".into(),
            error: None,
        });
    };
    Ok(
        match serde_json::from_slice::<super::SecodeBindingView>(incarnation) {
            Ok(binding)
                if found == session
                    && binding.schema == "se.secode-binding/v1"
                    && binding.session_id == *native_ref =>
            {
                Read::Present { value: binding }
            }
            _ => Read::Unreadable {
                source: "retained SE Code binding".into(),
                reason: "the original source is not a matching managed service binding".into(),
                error: None,
            },
        },
    )
}
