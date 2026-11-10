//! Atomic durable identity/profile creation; starting a process is a separate
//! custody operation. Configuration here is an already resolved adapter fact.
use super::{
    administration::{AgentCreate, AgentRename},
    inputs::Validate,
};
use crate::{
    commit::Cx,
    config_policy::{ConfigFile, EffectiveSandbox, Provider},
    dispatch::{Kernel, admitted},
    scope,
    store_error::store_error,
};
use se_store::{
    Actor, AtomicBatch, EventBody, Expected, GrantKey, PermissionProfile, PrincipalKind, Profile,
    Snapshot,
};
use se_types::{AgentId, Detail, IdempotencyKey, Read, Result, SeError, details};

pub struct AgentCreateThen {
    pub(crate) request: IdempotencyKey,
}
impl AgentCreateThen {
    pub fn request(&self) -> &IdempotencyKey {
        &self.request
    }
}
pub fn create<R: Snapshot>(
    kernel: &Kernel,
    input: AgentCreate,
    configuration: &ConfigFile,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, AgentCreateThen)> {
    input.validate()?;
    configuration.validate()?;
    admitted(cx)?;
    let project = scope::require_present(
        cx.read
            .project(scope::project(cx.admission)?)
            .map_err(|error| store_error(&error))?,
        "agent creation project",
        "Select an initialized project in this data home before adding an agent.",
    )?;
    let original = project.original.as_deref().unwrap_or(&project.current);
    let EventBody::ProjectRegistered { owner, .. } = &original.body else {
        return Err(scope::unreadable(
            "agent creation project",
            "original owner registration is unavailable",
        ));
    };
    if let Actor::Agent(creator) = &cx.admission.actor {
        let grant = cx
            .read
            .grant(
                Actor::Agent(creator.clone()),
                GrantKey::AgentCanCreate(creator.clone()),
            )
            .map_err(|error| store_error(&error))?;
        match grant {
            Read::Present { value }
                if matches!(
                    value.current.body,
                    EventBody::GrantRecorded { active: true, .. }
                ) => {}
            Read::Absent { .. } | Read::Present { .. } => {
                return Err(SeError::new(Detail::OwnerRequired(
                    details::OwnerRequired {
                        op: "agent.create without a current create grant".into(),
                    },
                )));
            }
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
            Read::Unknown { what } => return Err(scope::unreadable("agent creation grant", &what)),
        }
    }
    let normalized = serde_json::to_value(&input)
        .map_err(|error| scope::unreadable("agent creation intent", &error.to_string()))?;
    let provider = input.provider.unwrap_or(configuration.launch.provider);
    let defaults = match provider {
        Provider::Claude => &configuration.providers.claude,
        Provider::Codex => &configuration.providers.codex,
        Provider::SeCode => &configuration.providers.secode,
        Provider::Acp => &configuration.providers.acp,
    };
    let permission = match configuration
        .resolve_profile(&defaults.profile, provider, false)?
        .sandbox
    {
        EffectiveSandbox::ReadOnly => PermissionProfile::ReadOnly,
        EffectiveSandbox::WorkspaceWrite => PermissionProfile::WorkspaceWrite,
        EffectiveSandbox::Bypass => PermissionProfile::NamedFullBypass,
    };
    let model = input
        .model
        .or_else(|| (!defaults.model.is_empty()).then(|| defaults.model.clone()));
    let facts = kernel.facts()?;
    let agent = facts.agent.clone();
    let identity = kernel.event(
        EventBody::PrincipalRegistered {
            principal: Actor::Agent(agent.clone()),
            kind: PrincipalKind::Agent,
            owner: owner.clone(),
            created_by: Some(cx.admission.actor.clone()),
            name: input.name,
            role: String::new(),
            expected: Expected::Absent,
        },
        cx,
    )?;
    let mut profile = kernel.event(
        EventBody::ProfileSaved {
            agent,
            profile: Profile {
                provider: match provider {
                    Provider::Claude => se_store::Provider::Claude,
                    Provider::Codex => se_store::Provider::Codex,
                    Provider::SeCode => se_store::Provider::SeCode,
                    Provider::Acp => se_store::Provider::Acp,
                },
                model,
                permission,
                named_profile: defaults.profile.clone(),
                effort: None,
            },
            expected: Expected::Absent,
        },
        cx,
    )?;
    profile.header.event = facts.profile_event.clone();
    let key = input.idempotency_key;
    let mut batch = kernel.batch("agent.create", key.clone(), normalized, identity, cx)?;
    batch.events.push(profile);
    Ok((batch, AgentCreateThen { request: key }))
}

pub fn committed<R: Snapshot>(
    then: AgentCreateThen,
    receipt: se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::AgentReceipt> {
    super::receipt::receipt_key(&receipt, &then.request, "agent creation receipt")?;
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "agent creation receipt",
            "committed scope/actor differs",
        ));
    }
    let commit = super::receipt::write_fields(&receipt, &event)?;
    let EventBody::PrincipalRegistered {
        principal: Actor::Agent(agent),
        name,
        ..
    } = event.body
    else {
        return Err(scope::unreadable(
            "agent creation receipt",
            "primary event is not an agent registration",
        ));
    };
    let mut profile = None;
    for id in &receipt.events {
        let member = scope::require_present(
            cx.read
                .event(id.clone())
                .map_err(|error| store_error(&error))?,
            "agent receipt member",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if let EventBody::ProfileSaved {
            agent: target,
            profile: saved,
            ..
        } = member.body
        {
            if target != agent
                || profile.is_some()
                || member.header.scope != cx.admission.scope
                || member.header.actor != cx.admission.actor
            {
                return Err(scope::unreadable(
                    "agent profile receipt",
                    "member does not match its original creation",
                ));
            }
            profile = Some(saved);
        }
    }
    let profile = profile.ok_or_else(|| {
        scope::unreadable(
            "agent creation receipt",
            "atomic original profile event is absent",
        )
    })?;
    let provider = match profile.provider {
        se_store::Provider::Claude => Provider::Claude,
        se_store::Provider::Codex => Provider::Codex,
        se_store::Provider::SeCode => Provider::SeCode,
        se_store::Provider::Acp => Provider::Acp,
    };
    Ok(super::AgentReceipt {
        commit,
        action: super::AgentAction::Create,
        outcome: if receipt.state == se_store::CommitState::Committed {
            super::AgentOutcome::Created
        } else {
            super::AgentOutcome::Existing
        },
        agent: super::AgentReceiptValue {
            id: agent,
            name,
            provider,
            model: profile.model,
            profile: profile.named_profile,
        },
        previous_name: None,
        process_started: super::NoProcessStarted,
    })
}

pub struct AgentRenameThen {
    pub(crate) request: IdempotencyKey,
    pub(crate) agent: AgentId,
    pub(crate) previous_name: String,
}
fn replay_target<R: Snapshot>(key: &IdempotencyKey, cx: &mut Cx<'_, R>) -> Result<Option<AgentId>> {
    let receipt = cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|error| store_error(&error))?;
    match receipt {
        Read::Present { value } => {
            let event = super::receipt::committed_event(cx.read, &value)?;
            match event.body {
                EventBody::PrincipalRenamed {
                    principal: Actor::Agent(agent),
                    ..
                } => Ok(Some(agent)),
                _ => Err(SeError::new(se_types::Detail::IdempotencyKeyReused(
                    se_types::details::IdempotencyKeyReused {
                        key: key.to_string(),
                        original_event: value.primary_event,
                    },
                ))),
            }
        }
        Read::Absent { .. } => Ok(None),
        other => {
            scope::require_present(
                other,
                "agent rename request identity",
                "Read the original agent rename request in this project and retry with the same --key; do not allocate a new key.",
            )?;
            Ok(None)
        }
    }
}
pub fn rename<R: Snapshot>(
    kernel: &Kernel,
    input: AgentRename,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, AgentRenameThen)> {
    input.validate()?;
    admitted(cx)?;
    if !matches!(cx.admission.actor, Actor::Human(_)) {
        return Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired {
                op: "agent.rename".into(),
            },
        )));
    }
    let agent = match replay_target(&input.idempotency_key, cx)? {
        Some(agent) => agent,
        None => match scope::selected_actor(cx, &input.agent)? {
            Actor::Agent(agent) => agent,
            Actor::Human(_) | Actor::Remote(_) => {
                return Err(SeError::invalid(
                    "agent selector",
                    "a saved agent, not the owner",
                ));
            }
        },
    };
    let principal = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|error| store_error(&error))?,
        "agent rename target",
        "Select an existing saved agent in this project, using its exact agent ID or registered name.",
    )?;
    let previous_name = match &principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name.clone()
        }
        _ => {
            return Err(scope::unreadable(
                "agent rename target",
                "current event is not principal registration or rename",
            ));
        }
    };
    let intent = serde_json::to_value(&input)
        .map_err(|error| scope::unreadable("agent rename intent", &error.to_string()))?;
    let body = EventBody::PrincipalRenamed {
        principal: Actor::Agent(agent.clone()),
        name: input.name,
        expected: Expected::Revision(principal.revision),
    };
    let event = kernel.event(body, cx)?;
    let batch = kernel.batch(
        "agent.rename",
        input.idempotency_key.clone(),
        intent,
        event,
        cx,
    )?;
    Ok((
        batch,
        AgentRenameThen {
            request: input.idempotency_key,
            agent,
            previous_name,
        },
    ))
}
pub fn rename_committed<R: Snapshot>(
    then: AgentRenameThen,
    receipt: se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::AgentReceipt> {
    super::receipt::receipt_key(&receipt, &then.request, "agent rename receipt")?;
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "agent rename receipt",
            "committed scope/actor differs",
        ));
    }
    let commit = super::receipt::write_fields(&receipt, &event)?;
    let EventBody::PrincipalRenamed {
        principal: Actor::Agent(agent),
        name,
        ..
    } = event.body
    else {
        return Err(scope::unreadable(
            "agent rename receipt",
            "primary event is not an agent rename",
        ));
    };
    if agent != then.agent {
        return Err(scope::unreadable(
            "agent rename receipt",
            "committed principal differs from the planned target",
        ));
    }
    let saved = scope::require_present(
        cx.read
            .profile(agent.clone())
            .map_err(|error| store_error(&error))?,
        "agent rename profile",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let EventBody::ProfileSaved {
        profile,
        agent: target,
        ..
    } = saved.current.body
    else {
        return Err(scope::unreadable(
            "agent rename profile",
            "current event is not a saved profile",
        ));
    };
    if target != agent {
        return Err(scope::unreadable(
            "agent rename profile",
            "saved profile differs from the renamed agent",
        ));
    }
    let provider = match profile.provider {
        se_store::Provider::Claude => Provider::Claude,
        se_store::Provider::Codex => Provider::Codex,
        se_store::Provider::SeCode => Provider::SeCode,
        se_store::Provider::Acp => Provider::Acp,
    };
    let outcome = match receipt.state {
        se_store::CommitState::Committed if name != then.previous_name => {
            super::AgentOutcome::Renamed
        }
        _ => super::AgentOutcome::Unchanged,
    };
    Ok(super::AgentReceipt {
        commit,
        action: super::AgentAction::Rename,
        outcome,
        agent: super::AgentReceiptValue {
            id: agent,
            name,
            provider,
            model: profile.model,
            profile: profile.named_profile,
        },
        previous_name: Some(then.previous_name),
        process_started: super::NoProcessStarted,
    })
}
