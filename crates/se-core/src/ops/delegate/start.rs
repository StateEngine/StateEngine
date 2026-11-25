//! Planning and atomic principal/profile creation for `delegate.start`.
use super::{DEFAULT_HANDOFF_BYTES, DelegateStart, DelegateStartPlan, MAX_TASK_BYTES};
use crate::{
    commit::Cx,
    dispatch::{Kernel, admitted},
    ops::{
        continuity::handoff::{HandoffExport, export as export_handoff},
        inputs::Validate,
        process_commit, receipt,
    },
    scope,
    store_error::store_error,
};
use se_config::config_policy::{ConfigFile, EffectiveSandbox, Provider};
use se_store::{
    Actor, AtomicBatch, EphemeralSpec, EventBody, Expected, GrantKey, PermissionProfile,
    PrincipalKind, Profile, ReadBudget, Snapshot,
};
use se_types::{
    AgentId, Detail, IdempotencyKey, Named, NativePath, PageRequest, ProjectId, Read, Result,
    SeError, details,
};
use std::{num::NonZeroU32, time::Duration};

pub fn plan_start<R: Snapshot>(
    kernel: &Kernel,
    input: DelegateStart,
    configuration: Option<&ConfigFile>,
    cx: &mut Cx<'_, R>,
) -> Result<DelegateStartPlan> {
    let configuration = configuration.ok_or_else(|| {
        scope::unreadable(
            "delegation configuration",
            "adapter-resolved ConfigFile is not bound",
        )
    })?;
    input.validate()?;
    configuration.validate()?;
    admitted(cx)?;
    let (project_id, owner, project_name, cwd) = project_facts(cx)?;
    require_delegate_authority(cx)?;
    let binding =
        crate::harness_selection::resolve(configuration, input.provider, input.harness.as_deref())?;
    let provider = binding.provider;
    let defaults = configuration.provider(provider);
    let named_profile = input
        .profile
        .clone()
        .unwrap_or_else(|| defaults.profile.clone());
    if matches!(cx.admission.actor, Actor::Agent(_)) {
        configuration
            .delegation
            .require_allowed(provider, &named_profile)?;
    }
    let resolved = configuration.resolve_profile(&named_profile, provider, true)?;
    let permission = match resolved.sandbox {
        EffectiveSandbox::ReadOnly => PermissionProfile::ReadOnly,
        EffectiveSandbox::WorkspaceWrite => PermissionProfile::WorkspaceWrite,
        EffectiveSandbox::Bypass => PermissionProfile::NamedFullBypass,
    };
    let configured_ttl = configuration.delegation.ttl_seconds();
    let ttl_seconds = input
        .ttl_seconds
        .map_or(configured_ttl, |requested| requested.min(configured_ttl));
    let max_active_per_parent = configuration.delegation.max_active_per_parent();
    let existing_agent = find_replayed_agent(&input.idempotency_key, cx)?;
    if existing_agent.is_none() {
        enforce_active_child_cap(max_active_per_parent, cx)?;
    }
    let (composed_task, handoff_included) = compose_task(&input, cx)?;
    let model = input
        .model
        .clone()
        .or_else(|| (!defaults.model.is_empty()).then(|| defaults.model.clone()));
    let role = input
        .role
        .clone()
        .unwrap_or_else(|| "helper".to_owned())
        .to_ascii_lowercase();
    let agent_id = kernel.facts()?.agent.clone();
    let suffix = short_hex(&agent_id);
    let name = format!("tmp-{role}-{suffix}");
    let normalized_intent = serde_json::to_value(&input)
        .map_err(|error| scope::unreadable("delegate intent", &error.to_string()))?;
    Ok(DelegateStartPlan {
        project: Named {
            id: project_id,
            name: project_name,
        },
        owner,
        creator: cx.admission.actor.clone(),
        cwd,
        agent_id,
        name,
        role,
        provider,
        stored_provider: to_stored_provider(provider),
        harness: binding.harness,
        model,
        named_profile,
        permission,
        resolved,
        ephemeral: EphemeralSpec {
            one_shot: true,
            ttl_seconds,
        },
        max_active_per_parent,
        composed_task,
        handoff_included,
        idempotency_key: input.idempotency_key,
        normalized_intent,
        existing_agent,
    })
}

/// Build the atomic `PrincipalRegistered { ephemeral: Some(..) } + ProfileSaved`
/// batch for a qualified `DelegateStartPlan`, rechecking the active-child cap
/// on the fresh commit snapshot so concurrent requests cannot race past it.
pub fn create_ephemeral_batch<R: Snapshot>(
    kernel: &Kernel,
    plan: &DelegateStartPlan,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    if find_replayed_agent(&plan.idempotency_key, cx)?.is_none() {
        enforce_active_child_cap(plan.max_active_per_parent, cx)?;
    }
    let identity = EventBody::PrincipalRegistered {
        principal: Actor::Agent(plan.agent_id.clone()),
        kind: PrincipalKind::Agent,
        owner: plan.owner.clone(),
        created_by: Some(plan.creator.clone()),
        name: plan.name.clone(),
        role: plan.role.clone(),
        ephemeral: Some(plan.ephemeral),
        expected: Expected::Absent,
    };
    let profile = EventBody::ProfileSaved {
        agent: plan.agent_id.clone(),
        profile: Profile {
            provider_settings: Default::default(),
            provider: plan.stored_provider,
            model: plan.model.clone(),
            permission: plan.permission,
            harness: plan.harness.clone(),
            named_profile: plan.named_profile.clone(),
            effort: None,
        },
        expected: Expected::Absent,
    };
    process_commit::batch(
        kernel,
        "delegate.start",
        plan.idempotency_key.clone(),
        plan.normalized_intent.clone(),
        vec![identity, profile],
        cx,
    )
}

/// Paginate across all active principals in the project and refuse if this
/// parent already has `cap` or more active temporary children.
pub fn enforce_active_child_cap<R: Snapshot>(cap: u32, cx: &mut Cx<'_, R>) -> Result<()> {
    let mut after = None;
    let mut active_children: u32 = 0;
    loop {
        let budget = ReadBudget {
            page: PageRequest {
                after: after.clone(),
                limit: NonZeroU32::new(256).ok_or_else(|| SeError::invalid("limit", "positive"))?,
                max_bytes: NonZeroU32::new(512 * 1024)
                    .ok_or_else(|| SeError::invalid("bytes", "positive"))?,
            },
            deadline: Duration::from_secs(2),
        };
        let page = cx
            .read
            .active_principals(budget)
            .map_err(|error| store_error(&error))?;
        let next = page.next().cloned();
        for record in page.into_items() {
            let original = record.original.as_deref().unwrap_or(&record.current);
            if let EventBody::PrincipalRegistered {
                created_by,
                ephemeral: Some(_),
                ..
            } = &original.body
                && created_by.as_ref() == Some(&cx.admission.actor)
            {
                active_children = active_children.saturating_add(1);
                if active_children >= cap {
                    return Err(SeError::new(Detail::StateConflict(
                        details::StateConflict {
                            subject: "delegate.start".into(),
                            reason: format!(
                                "parent already has {active_children} active temporary agents (cap is {cap})"
                            ),
                            next_step: "Wait for an active temporary agent to finish or cancel one with se delegate cancel <agent>.".into(),
                        },
                    )));
                }
            }
        }
        match next {
            Some(cursor) => after = Some(cursor),
            None => return Ok(()),
        }
    }
}

fn require_delegate_authority<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<()> {
    let Actor::Agent(creator) = &cx.admission.actor else {
        return Ok(());
    };
    if let Read::Present { value } = cx
        .read
        .principal(Actor::Agent(creator.clone()))
        .map_err(|error| store_error(&error))?
    {
        let original = value.original.as_deref().unwrap_or(&value.current);
        if matches!(
            original.body,
            EventBody::PrincipalRegistered {
                ephemeral: Some(_),
                ..
            }
        ) {
            return Err(SeError::new(Detail::StateConflict(
                details::StateConflict {
                    subject: "delegate.start".into(),
                    reason: "temporary agents cannot delegate grandchildren (depth limit is 1)"
                        .into(),
                    next_step:
                        "Return your result to the parent agent instead of delegating further."
                            .into(),
                },
            )));
        }
    }
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
            ) =>
        {
            Ok(())
        }
        Read::Absent { .. } | Read::Present { .. } => Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired {
                op: "delegate.start without an active agent create grant (set via se config set agent.<name>.can-create true)".into(),
            },
        ))),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => Err(scope::unreadable("delegate create grant", &what)),
    }
}

fn find_replayed_agent<R: Snapshot>(
    key: &IdempotencyKey,
    cx: &mut Cx<'_, R>,
) -> Result<Option<(AgentId, String)>> {
    let record = match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => value,
        Read::Absent { .. } => return Ok(None),
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("delegate idempotency", &what)),
    };
    let event = receipt::committed_event(cx.read, &record)?;
    match event.body {
        EventBody::PrincipalRegistered {
            principal: Actor::Agent(agent),
            name,
            ..
        } => Ok(Some((agent, name))),
        _ => Err(scope::unreadable(
            "delegated agent registration",
            "idempotency record does not point to a principal registration",
        )),
    }
}

fn compose_task<R: Snapshot>(input: &DelegateStart, cx: &mut Cx<'_, R>) -> Result<(String, bool)> {
    let Some(handoff) = &input.handoff else {
        return Ok((input.task.clone(), false));
    };
    let exported = export_handoff(
        HandoffExport {
            from: handoff.from.clone(),
            budget: handoff.budget.unwrap_or(DEFAULT_HANDOFF_BYTES),
            since: handoff.since.clone(),
        },
        cx,
    )?;
    let composed = format!("{}\n\n---\n\n{}", exported.text, input.task);
    if composed.len() > MAX_TASK_BYTES {
        return Err(SeError::too_large(
            "delegate task with handoff",
            MAX_TASK_BYTES,
            composed.len(),
        ));
    }
    Ok((composed, true))
}

fn project_facts<R: Snapshot>(
    cx: &mut Cx<'_, R>,
) -> Result<(ProjectId, se_types::HumanId, String, NativePath)> {
    let id = scope::project(cx.admission)?;
    let project = scope::require_present(
        cx.read
            .project(id.clone())
            .map_err(|error| store_error(&error))?,
        "delegation project",
        "Select an initialized project in this data home before delegating.",
    )?;
    let owner = match &project.original.as_deref().unwrap_or(&project.current).body {
        EventBody::ProjectRegistered { owner, .. } => owner.clone(),
        _ => {
            return Err(scope::unreadable(
                "delegation project",
                "original owner registration is unavailable",
            ));
        }
    };
    let (name, roots) = match project.current.body {
        EventBody::ProjectRegistered { name, roots, .. }
        | EventBody::ProjectUpdated { name, roots, .. } => (name, roots),
        EventBody::ProjectMoved { name, to, .. } => (name, vec![to]),
        _ => {
            return Err(scope::unreadable(
                "delegation project",
                "project projection has the wrong event kind",
            ));
        }
    };
    let cwd = roots
        .first()
        .ok_or_else(|| scope::unreadable("delegation project", "project has no registered root"))?
        .path
        .clone();
    Ok((id, owner, name, cwd))
}

fn short_hex(agent: &AgentId) -> String {
    let raw = agent.as_str();
    let hex: String = raw
        .chars()
        .rev()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if hex.len() == 8 {
        hex.to_ascii_lowercase()
    } else {
        "00000000".to_owned()
    }
}

fn to_stored_provider(provider: Provider) -> se_store::Provider {
    match provider {
        Provider::Claude => se_store::Provider::Claude,
        Provider::Codex => se_store::Provider::Codex,
        Provider::SeCode => se_store::Provider::SeCode,
        Provider::Acp => se_store::Provider::Acp,
    }
}
