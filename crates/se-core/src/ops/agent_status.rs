//! Saved identity readback. Native lifecycle and provider conversation facts are
//! deliberately unknown until the runtime observation adapter supplies them.
use super::{AgentRow, AgentShow, AgentStatusOutput, ConversationView, ResumeCommand, SessionView};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, EventBody, Snapshot};
use se_types::{Read, Result, SeError};

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
