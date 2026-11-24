//! Finite control-target selection and policy resolution. No native resources or
//! private child history enter these owned plans.
use super::{
    agent_launch::{AgentLaunch, LaunchPlan},
    inputs::Validate,
};
use crate::{commit::Cx, dispatch::Kernel, scope, store_error::store_error};
use se_config::config_policy::{ConfigFile, EffectiveSandbox, Provider};
use se_store::{Actor, EventBody, PermissionProfile, Snapshot};
use se_types::{
    AgentId, Detail, Named, ProviderSessionId, Read, Result, ResumeSelection, SeError,
    details::{CapabilityInvalid, LaunchFailed},
};

fn imported_reference(reference: Read<ProviderSessionId>) -> Result<Read<ProviderSessionId>> {
    if matches!(reference, Read::Absent { .. }) {
        return Err(SeError::invalid(
            "imported Codex conversation",
            "a retained native thread reference; omit --resume when it is missing or unsupported",
        ));
    }
    Ok(reference)
}

pub fn target<R: Snapshot>(
    selected: Option<&AgentId>,
    selector: Option<&str>,
    cx: &mut Cx<'_, R>,
) -> Result<AgentId> {
    if let Some(selector) = selector {
        if selected.is_some() {
            return Err(SeError::invalid(
                "agent selector",
                "one exact ID or CLI name",
            ));
        }
        return match scope::selected_actor(cx, selector)? {
            Actor::Agent(agent) => Ok(agent),
            Actor::Human(_) | Actor::Remote(_) | Actor::Guest => {
                Err(SeError::invalid("launch target", "a saved agent"))
            }
        };
    }
    match (selected, &cx.admission.actor) {
        (Some(agent), _) => Ok(agent.clone()),
        (None, Actor::Agent(agent)) => Ok(agent.clone()),
        (None, Actor::Human(_) | Actor::Remote(_) | Actor::Guest) => {
            Err(SeError::invalid("agent selector", "--agent AGENT"))
        }
    }
}
pub fn launch<R: Snapshot>(
    kernel: &Kernel,
    mut input: AgentLaunch,
    configuration: &ConfigFile,
    cx: &mut Cx<'_, R>,
) -> Result<LaunchPlan> {
    input.validate()?;
    let agent = target(
        input.target_agent_id.as_ref(),
        input.owner_agent.as_deref(),
        cx,
    )?;
    let mut control = scope::require_present(
        cx.read
            .control_target(agent.clone())
            .map_err(|e| store_error(&e))?,
        "launch target",
        "Choose a saved agent in this project that you own or are currently allowed to control.",
    )?;
    let name = match &control.principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name.clone()
        }
        _ => {
            return Err(scope::unreadable(
                "launch target",
                "principal projection has the wrong event kind",
            ));
        }
    };
    let saved = scope::require_present(
        control.profile.clone(),
        "saved launch profile",
        "Save a profile for this agent before launching it.",
    )?;
    let (mut profile, provider) = saved_profile(&mut input, &control, saved)?;
    let resolved = configuration.resolve_profile(&profile.named_profile, provider, input.detach)?;
    let permission = match resolved.sandbox {
        EffectiveSandbox::ReadOnly => PermissionProfile::ReadOnly,
        EffectiveSandbox::WorkspaceWrite => PermissionProfile::WorkspaceWrite,
        EffectiveSandbox::Bypass => PermissionProfile::NamedFullBypass,
    };
    if permission != profile.permission {
        return Err(SeError::invalid(
            "saved launch permissions",
            "save the changed named profile explicitly before launching",
        ));
    }
    if let Some(model) = &input.model {
        profile.model = Some(model.clone());
    }
    let (id, owner, project_name, cwd) = project_facts(cx)?;
    let (seed, replayed) = launch_seed(kernel, cx, &input, &agent)?;
    let identity = LaunchIdentity {
        project: id.clone(),
        agent: agent.clone(),
        name: name.clone(),
    };
    let conversation =
        select_conversation(cx, &input, &mut control, &profile, &identity, replayed)?;
    let saved_conversation_age = conversation_age(kernel, &control, &conversation)?;
    let bytes = seed
        .canonical_bytes()?
        .ok_or_else(|| SeError::invalid("launch allocation", "canonical UUIDv7 event identity"))?;
    Ok(LaunchPlan {
        remote: None,
        channel_resume: None,
        input,
        owner,
        project: Named {
            id,
            name: project_name,
        },
        agent: Named { id: agent, name },
        cwd,
        profile,
        resolved,
        conversation,
        saved_conversation_age,
        capture: configuration.capture.enabled,
        control,
        seed,
        replayed,
        session: se_types::SessionId::from_bytes(bytes)?,
        lifecycle: se_types::LifecycleId::from_bytes(bytes)?,
    })
}
/// Identity facts the launch plan carries into its refusal and repair messages.
struct LaunchIdentity {
    project: se_types::ProjectId,
    agent: AgentId,
    name: String,
}
fn saved_profile(
    input: &mut AgentLaunch,
    control: &se_store::ControlTarget,
    saved: se_store::ProjectionRecord,
) -> Result<(se_store::Profile, Provider)> {
    let EventBody::ProfileSaved { profile, .. } = saved.current.body else {
        return Err(scope::unreadable(
            "launch profile",
            "wrong immutable profile event",
        ));
    };
    let provider = match profile.provider {
        se_store::Provider::Claude => Provider::Claude,
        se_store::Provider::Codex => Provider::Codex,
        se_store::Provider::SeCode => Provider::SeCode,
        se_store::Provider::Acp => Provider::Acp,
    };
    if matches!(provider, Provider::SeCode | Provider::Acp) && input.override_live {
        input.detach = true;
    }
    if control.processes.is_empty() && control.sessions.is_empty() {
        input.require_launch_mode(profile.provider)?;
    }
    if input
        .owner_provider
        .is_some_and(|selected| selected != provider)
    {
        return Err(SeError::invalid(
            "provider",
            "the saved agent's provider; create another agent to use a different provider",
        ));
    }
    Ok((profile, provider))
}
fn project_facts<R: Snapshot>(
    cx: &mut Cx<'_, R>,
) -> Result<(
    se_types::ProjectId,
    se_types::HumanId,
    String,
    se_types::NativePath,
)> {
    let id = scope::project(cx.admission)?;
    let project = scope::require_present(
        cx.read.project(id.clone()).map_err(|e| store_error(&e))?,
        "launch project",
        "Initialize and select this project before launch.",
    )?;
    let owner = match &project.original.as_deref().unwrap_or(&project.current).body {
        EventBody::ProjectRegistered { owner, .. } => owner.clone(),
        _ => {
            return Err(scope::unreadable(
                "launch project owner",
                "original owner registration is unavailable",
            ));
        }
    };
    let (project_name, roots) = match project.current.body {
        EventBody::ProjectRegistered { name, roots, .. }
        | EventBody::ProjectUpdated { name, roots, .. } => (name, roots),
        EventBody::ProjectMoved { name, to, .. } => (name, vec![to.clone()]),
        _ => return Err(SeError::invalid("launch project", "an active project")),
    };
    let cwd = roots
        .first()
        .ok_or_else(|| scope::unreadable("launch project", "registered project has no root"))?
        .path
        .clone();
    Ok((id, owner, project_name, cwd))
}
fn launch_seed<R: Snapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, R>,
    input: &AgentLaunch,
    agent: &AgentId,
) -> Result<(se_types::EventId, bool)> {
    let replay = cx
        .read
        .operation_receipt(cx.admission.actor.clone(), input.idempotency_key.clone())
        .map_err(|e| store_error(&e))?;
    let replay = match replay {
        Read::Absent { .. } => None,
        read => Some(scope::require_present(
            read,
            "launch request receipt",
            scope::COMMITTED_READ_RECOVERY,
        )?),
    };
    let replayed = replay.is_some();
    let seed = match replay {
        None => kernel.facts()?.event.clone(),
        Some(value) => {
            let event = super::receipt::committed_event(cx.read, &value)?;
            if !matches!(
                event.body,
                EventBody::SessionPrepared {
                    agent: ref target,
                    ..
                } if target == agent
            ) {
                return Err(SeError::invalid(
                    "launch request key",
                    "the original launch target and request arguments",
                ));
            }
            event.header.event
        }
    };
    Ok((seed, replayed))
}
fn private_resume_refusal(input: &AgentLaunch, identity: &LaunchIdentity) -> SeError {
    let mut command =
        super::AgentCommand::launch(&identity.agent, None, Some(&identity.project), false)
            .with_detach(input.detach);
    if let Some(ResumeSelection::Session(session)) = &input.resume {
        command = command.with_resume_session(session);
    }
    SeError::new(Detail::CapabilityInvalid(CapabilityInvalid {
        subject: format!("saved conversation for {}", identity.name),
        reason: "a create grant does not authorize resuming another agent's saved conversation"
            .into(),
        next_step: format!(
            "Omit resume to launch a fresh conversation for this child, or ask the project Owner to resume its saved conversation from their own terminal with the same StateEngine home: `{}`.",
            command.command
        ),
    }))
}
fn select_conversation<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    input: &AgentLaunch,
    control: &mut se_store::ControlTarget,
    profile: &se_store::Profile,
    identity: &LaunchIdentity,
    replayed: bool,
) -> Result<Read<ProviderSessionId>> {
    if replayed {
        // The host reuses the retained outcome or refuses an unavailable retry.
        return Ok(Read::Unknown {
            what: "a launch retry reuses its original outcome; no new conversation was selected"
                .into(),
        });
    }
    if input.fresh() {
        return Ok(Read::Absent {
            checked:
                "launch starts a fresh provider conversation unless resume is explicitly requested"
                    .into(),
        });
    }
    // Creator control authorizes launching a direct child fresh, never
    // resuming another principal's saved conversation or reading its capture.
    if matches!(&cx.admission.actor, Actor::Agent(caller) if caller != &identity.agent) {
        return Err(private_resume_refusal(input, identity));
    }
    if let Some(ResumeSelection::Session(session)) = &input.resume {
        let selected = cx
            .read
            .control_session(identity.agent.clone(), session.clone())
            .map_err(|error| store_error(&error))?;
        control.resume_session = Read::Present {
            value: scope::require_present(
                selected,
                "selected saved conversation",
                "Use a saved session ID belonging to this agent, or omit --resume for a fresh conversation.",
            )?,
        };
    }
    match resumed_conversation(cx, control, profile, &identity.agent) {
        Ok(conversation) => Ok(conversation),
        Err(failure) if matches!(failure.body.detail(), Detail::CapabilityInvalid(_)) => {
            Err(private_resume_refusal(input, identity))
        }
        Err(failure) if input.override_live => Ok(Read::Absent {
            checked: format!(
                "Forced relaunch preserves the previous history and starts a fresh conversation because the saved binding could not be resumed: {failure}"
            ),
        }),
        Err(failure) if !control.processes.is_empty() || !control.sessions.is_empty() => {
            Ok(Read::Unknown {
                what: format!(
                    "Saved conversation unavailable before live-launch confirmation: {failure}"
                ),
            })
        }
        Err(failure) => Err(SeError::new(Detail::LaunchFailed(LaunchFailed {
            subject: identity.name.clone(),
            reason: failure.to_string(),
            next_step: "Repair the saved binding before resuming, or omit --resume to preserve the old history and start a fresh conversation.".into(),
        }))),
    }
}
fn resumed_conversation<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    control: &se_store::ControlTarget,
    profile: &se_store::Profile,
    agent: &AgentId,
) -> Result<Read<ProviderSessionId>> {
    Ok(match &control.resume_session {
        Read::Absent { .. } => {
            return Err(SeError::invalid(
                "resume conversation",
                "a saved conversation; omit --resume to start a fresh one",
            ));
        }
        Read::Present { value }
            if value
                .original
                .as_deref()
                .unwrap_or(&value.current)
                .header
                .door
                == se_store::Door::Import
                && profile.provider != se_store::Provider::Codex =>
        {
            return Err(SeError::invalid(
                "resume conversation",
                "a resumable native conversation; imported history alone cannot reopen this provider, so omit --resume for a fresh conversation",
            ));
        }
        Read::Present { value } if super::agent_launch::retryable_attended_setup(value) => {
            return Err(SeError::invalid(
                "resume conversation",
                "an activated conversation; omit --resume to retry the expired window setup",
            ));
        }
        Read::Present { value } => {
            // Only an activated conversation is resumable. A revoked
            // preparation is not silently replaced with a new conversation.
            if !matches!(
                value.current.body,
                EventBody::SessionActivated { .. } | EventBody::SessionEnded { .. }
            ) {
                return Err(SeError::invalid(
                    "resume conversation",
                    "the last session never activated; omit --resume to start another conversation",
                ));
            }
            let original = value.original.as_deref().unwrap_or(&value.current);
            match &original.body {
                EventBody::SessionPrepared {
                    agent: owner,
                    provider,
                    ..
                } if owner == agent && *provider == profile.provider => {
                    let reference = super::session_reference::read(cx.read, value)?;
                    if original.header.door == se_store::Door::Import {
                        imported_reference(reference)?
                    } else {
                        reference
                    }
                }
                _ => {
                    return Err(scope::unreadable(
                        "resume conversation",
                        "the original provider binding is unavailable or changed",
                    ));
                }
            }
        }
        Read::Unreadable { .. } | Read::Unknown { .. } => {
            return Err(scope::unreadable(
                "resume conversation",
                "the latest provider binding is unreadable; repair it or omit --resume for a fresh conversation",
            ));
        }
    })
}
fn conversation_age(
    kernel: &Kernel,
    control: &se_store::ControlTarget,
    conversation: &Read<ProviderSessionId>,
) -> Result<Read<super::agent_launch::SavedConversationAge>> {
    Ok(match &conversation {
        Read::Present { .. } => match &control.resume_session {
            Read::Present { value } => {
                let original = value.original.as_deref().unwrap_or(&value.current);
                let started = super::receipt::event_time(original);
                let now = kernel.facts()?.occurred_at_us;
                let age_seconds = now
                    .checked_sub(started)
                    .and_then(|elapsed| u64::try_from(elapsed).ok())
                    .map(|elapsed| Read::Present {
                        value: elapsed / 1_000_000,
                    })
                    .unwrap_or_else(|| Read::Unknown {
                        what: "The saved session timestamp is later than the launch clock".into(),
                    });
                match super::receipt::timestamp(started) {
                    Ok(session_started_at) => Read::Present {
                        value: super::agent_launch::SavedConversationAge {
                            session_started_at,
                            age_seconds,
                        },
                    },
                    Err(error) => Read::Unreadable {
                        source: "saved session timestamp".into(),
                        reason: error.to_string(),
                        error: Some(Box::new(error.body)),
                    },
                }
            }
            Read::Absent { checked } => Read::Absent {
                checked: checked.clone(),
            },
            Read::Unknown { what } => Read::Unknown { what: what.clone() },
            Read::Unreadable {
                source,
                reason,
                error,
            } => Read::Unreadable {
                source: source.clone(),
                reason: reason.clone(),
                error: error.clone(),
            },
        },
        Read::Absent { .. } => Read::Absent {
            checked: "This launch starts a new conversation".into(),
        },
        _ => Read::Unknown {
            what: "A launch retry retains its original conversation selection and age".into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_import_keeps_its_repair_reason_instead_of_fresh_thread_advice() -> Result<()> {
        let reference = Read::Unreadable {
            source: "retained native binding".into(),
            reason: "the committed source record cannot be read".into(),
            error: None,
        };
        let retained = imported_reference(reference.clone())?;
        assert_eq!(retained, reference);
        let error = scope::require_present(
            retained,
            "saved Codex thread",
            "Repair the retained native binding before resuming.",
        )
        .err()
        .ok_or_else(|| SeError::invalid("unreadable native history", "a refusal"))?;
        assert_eq!(error.code(), se_types::Code::SourceUnreadable);
        let rendered = format!("{error:?}");
        assert!(rendered.contains("the committed source record cannot be read"));
        assert!(!rendered.contains("--new"));
        assert!(
            imported_reference(Read::Absent {
                checked: "the historical session contains no native reference".into(),
            })
            .is_err()
        );
        Ok(())
    }
}
