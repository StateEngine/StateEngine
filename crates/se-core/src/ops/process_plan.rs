//! Finite control-target selection and policy resolution. No native resources or
//! private child history enter these owned plans.
use super::{
    agent_launch::{AgentLaunch, LaunchPlan},
    inputs::Validate,
};
use crate::{
    commit::Cx,
    config_policy::{ConfigFile, EffectiveSandbox, Provider},
    dispatch::Kernel,
    scope,
    store_error::store_error,
};
use se_store::{Actor, EventBody, PermissionProfile, Snapshot};
use se_types::{AgentId, Named, ProviderSessionId, Read, Result, SeError};

fn imported_reference(reference: Read<ProviderSessionId>) -> Result<Read<ProviderSessionId>> {
    if matches!(reference, Read::Absent { .. }) {
        return Err(SeError::invalid(
            "imported Codex conversation",
            "a retained native thread reference; use --new explicitly when it is missing or unsupported",
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
            Actor::Human(_) | Actor::Remote(_) => {
                Err(SeError::invalid("launch target", "a saved agent"))
            }
        };
    }
    match (selected, &cx.admission.actor) {
        (Some(agent), _) => Ok(agent.clone()),
        (None, Actor::Agent(agent)) => Ok(agent.clone()),
        (None, Actor::Human(_) | Actor::Remote(_)) => {
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
    let control = scope::require_present(
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
    let EventBody::ProfileSaved { mut profile, .. } = saved.current.body else {
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
    if matches!(provider, Provider::SeCode | Provider::Acp) && !input.detach {
        if input.override_live {
            input.detach = true;
        } else {
            return Err(SeError::invalid(
                "protocol launch mode",
                "headless launch with --detach, or --force for a forced headless relaunch",
            ));
        }
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
    let replay = cx
        .read
        .operation_receipt(cx.admission.actor.clone(), input.idempotency_key.clone())
        .map_err(|e| store_error(&e))?;
    let replayed = matches!(&replay, Read::Present { .. });
    let seed = match replay {
        Read::Absent { .. } => kernel.facts()?.event.clone(),
        Read::Present { value } => {
            let event = super::receipt::committed_event(cx.read, &value)?;
            if !matches!(event.body, EventBody::SessionPrepared { agent: ref target, .. } if target == &agent)
            {
                return Err(SeError::invalid(
                    "launch request key",
                    "the original launch target and request arguments",
                ));
            }
            event.header.event
        }
        other => {
            return scope::require_present(
                other,
                "launch request receipt",
                scope::COMMITTED_READ_RECOVERY,
            )
            .map(|_| unreachable!());
        }
    };
    let conversation = match (|| -> Result<Read<ProviderSessionId>> {
        let conversation = if replayed {
            // The host reuses the retained outcome or refuses an unavailable retry.
            // Selecting a new conversation here also reads a child's private capture
            // source for Codex, which its creator is not entitled to inspect.
            Read::Unknown {
                what:
                    "a launch retry reuses its original outcome; no new conversation was selected"
                        .into(),
            }
        } else if input.fresh {
            Read::Absent {
                checked: "an explicitly new provider conversation was requested".into(),
            }
        } else {
            match &control.resume_session {
            Read::Absent { checked } => Read::Absent {
                checked: checked.clone(),
            },
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
                Read::Absent {
                    checked:
                        "imported sessions are historical; start a fresh provider conversation"
                            .into(),
                }
            }
            Read::Present { value } if super::agent_launch::retryable_attended_setup(value) => {
                Read::Absent {
                    checked: "the expired window setup or its unactivated replacement needs a new connection using the existing provider onboarding".into(),
                }
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
                        "the last session never activated; use --new to explicitly start another conversation",
                    ));
                }
                let original = value.original.as_deref().unwrap_or(&value.current);
                match &original.body {
                    EventBody::SessionPrepared {
                        agent: owner,
                        provider,
                        ..
                    } if owner == &agent && *provider == profile.provider => {
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
                    "the latest provider binding is unreadable; repair it or choose --new explicitly",
                ));
            }
        }
        };
        Ok(conversation)
    })() {
        Ok(conversation) => conversation,
        Err(failure) if input.override_live => Read::Absent {
            checked: format!(
                "Forced relaunch preserves the previous history and starts a new conversation because the saved binding could not be resumed: {failure}"
            ),
        },
        Err(failure) if !control.processes.is_empty() || !control.sessions.is_empty() => Read::Unknown {
            what: format!("Saved conversation unavailable before live-launch confirmation: {failure}"),
        },
        Err(failure) => return Err(SeError::new(se_types::Detail::LaunchFailed(se_types::details::LaunchFailed {
            subject: name.clone(), reason: failure.to_string(),
            next_step: "Repeat this launch with --force to preserve the old history and start a new conversation when its saved binding cannot be resumed.".into(),
        }))),
    };
    let saved_conversation_age = match &conversation {
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
            other => other.clone().map(|_| unreachable!()),
        },
        Read::Absent { .. } => Read::Absent {
            checked: "This launch starts a new conversation".into(),
        },
        _ => Read::Unknown {
            what: "A launch retry retains its original conversation selection and age".into(),
        },
    };
    let bytes = seed
        .canonical_bytes()?
        .ok_or_else(|| SeError::invalid("launch allocation", "canonical UUIDv7 event identity"))?;
    Ok(LaunchPlan {
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
