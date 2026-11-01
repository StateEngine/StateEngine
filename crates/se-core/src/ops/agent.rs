//! Atomic durable identity/profile creation; starting a process is a separate
//! custody operation. Configuration here is an already resolved adapter fact.
use super::{administration::AgentCreate, inputs::Validate};
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
use se_types::{Detail, IdempotencyKey, Read, Result, SeError, details};

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
    if receipt.request_key.as_ref() != Some(&then.request) {
        return Err(scope::unreadable(
            "agent creation receipt",
            "request identity differs",
        ));
    }
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
        se_store::Provider::SeCode => {
            return Err(scope::unreadable(
                "agent creation provider",
                "unexpected provider in a managed agent identity",
            ));
        }
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
