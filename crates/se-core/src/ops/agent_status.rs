//! Saved identity readback. Native lifecycle and provider conversation facts are
//! deliberately unknown until the runtime observation adapter supplies them.
use super::{AgentRow, AgentShow, AgentStatusOutput, ConversationView, ResumeCommand, SessionView};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, EventBody, Snapshot};
use se_types::{Read, Result, SeError};

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
        let mut row = scope::require_present(
            show(
                AgentShow {
                    target_agent_id: Some(agent.clone()),
                },
                cx,
            )?
            .agent,
            "saved agent page row",
        )?;
        row.unread = Some(
            cx.read
                .message_count(se_store::MessageQuery {
                    recipient: Some(Actor::Agent(agent)),
                    sender: None,
                    kind: None,
                    unread_only: true,
                    full_body: false,
                })
                .map_err(|e| store_error(&e))?,
        );
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
    let principal = cx
        .read
        .principal(Actor::Agent(agent.clone()))
        .map_err(|error| store_error(&error))?;
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
    let profile = cx
        .read
        .profile(agent.clone())
        .map_err(|error| store_error(&error))?;
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
        se_store::Provider::SeCode => {
            return Err(SeError::invalid(
                "provider",
                "a standalone Claude or Codex identity",
            ));
        }
    };
    Ok(AgentStatusOutput{agent:Read::Present{value:AgentRow{
        id:agent,name,role,provider,model:profile.model,profile:profile.named_profile,
        session:SessionView{state:"unknown".into(),session_id:None,launch_id:None,surface:"unknown".into(),process:None,since:None,observed_at:None,containment:None,containment_cause:Some("No native lifecycle observation was supplied to this saved-identity read.".into())},
        conversation:ConversationView{id:None,state:"unknown".into()},
        resume:ResumeCommand{ready:false,mode:"unknown".into(),reason:Some("Provider conversation and process custody have not been observed by this read.".into()),command:None,argv:None},unread:None,last_activity_at:None,
    }}})
}
