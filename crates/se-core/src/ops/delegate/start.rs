//! Planning and atomic principal/profile creation for `delegate.start`.
use super::{
    DEFAULT_HANDOFF_BYTES, DelegateStart, DelegateStartPlan, MAX_TASK_BYTES, RemoteDelegation,
};
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
use se_config::config_policy::{ConfigFile, DelegationConfig, EffectiveSandbox};
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
    require_delegate_authority("delegate.start", cx)?;
    let requester = match cx.admission.actor {
        Actor::Agent(_) => Requester::Agent,
        _ => Requester::Owner,
    };
    plan_worker(kernel, input, configuration, requester, cx)
}

/// Who asks for a worker; it decides the allowed pairs and the request identity.
pub(crate) enum Requester {
    /// The local Owner may choose any configured pair.
    Owner,
    /// A local agent may choose only a `[delegation].allow` pair.
    Agent,
    /// A paired machine may choose only a `[delegation].remote_allow` pair; its
    /// worker is created by the anchor.
    Remote(Box<RemoteRequest>),
}

/// A paired machine's request as it arrived, before this machine filled any
/// default from the anchor's saved profile, so a byte-identical retry keeps
/// its key even after the Owner edits that profile.
pub(crate) struct RemoteRequest {
    pub origin: RemoteDelegation,
    pub supplied: serde_json::Value,
}

type AllowCheck = fn(&DelegationConfig, se_config::config_policy::Provider, &str) -> Result<()>;

/// Plan one temporary worker once its caller's authority is checked.
pub(crate) fn plan_worker<R: Snapshot>(
    kernel: &Kernel,
    input: DelegateStart,
    configuration: &ConfigFile,
    requester: Requester,
    cx: &mut Cx<'_, R>,
) -> Result<DelegateStartPlan> {
    let (project_id, owner, project_name, cwd) = project_facts(cx)?;
    let allowlist = match &requester {
        Requester::Owner => None,
        Requester::Agent => Some(DelegationConfig::require_allowed as AllowCheck),
        Requester::Remote(_) => Some(DelegationConfig::require_remote_allowed as AllowCheck),
    };
    // The exact earlier request is found first: a retry continues its committed
    // worker, whose pair the first launch rechecks, even if the defaults this
    // request would now fill in have changed.
    let (remote, normalized_intent) = match requester {
        Requester::Remote(request) => {
            let RemoteRequest { origin, supplied } = *request;
            let intent = serde_json::json!({ "anchor": origin.anchor, "request": supplied });
            (Some(origin), intent)
        }
        Requester::Owner | Requester::Agent => (
            None,
            serde_json::to_value(&input)
                .map_err(|error| scope::unreadable("delegate intent", &error.to_string()))?,
        ),
    };
    let existing_agent = find_replayed_agent(
        kernel,
        operation(remote.as_ref()),
        &input.idempotency_key,
        &normalized_intent,
        cx,
    )?;
    // A retry continues from what its worker committed; only a new worker
    // takes this machine's current defaults and allowlist.
    let launch = match &existing_agent {
        Some((agent, _)) => committed_launch(agent, cx)?,
        None => new_launch(&input, configuration, allowlist)?,
    };
    let max_active_per_parent = configuration.delegation.max_active_per_parent();
    if existing_agent.is_none() {
        enforce_active_child_cap(max_active_per_parent, cx)?;
    }
    let (composed_task, handoff_included) = compose_task(&input, cx)?;
    let role = input
        .role
        .clone()
        .unwrap_or_else(|| "helper".to_owned())
        .to_ascii_lowercase();
    let agent_id = kernel.facts()?.agent.clone();
    let suffix = short_hex(&agent_id);
    let name = format!("tmp-{role}-{suffix}");
    Ok(DelegateStartPlan {
        project: Named {
            id: project_id,
            name: project_name,
        },
        owner,
        creator: match &remote {
            Some(origin) => Actor::Agent(origin.anchor.agent.clone()),
            None => cx.admission.actor.clone(),
        },
        cwd,
        agent_id,
        name,
        role,
        provider: launch.provider,
        stored_provider: launch.provider.into(),
        harness: launch.harness,
        model: launch.model,
        named_profile: launch.named_profile,
        permission: launch.permission,
        ephemeral: EphemeralSpec {
            one_shot: true,
            ttl_seconds: launch.ttl_seconds,
        },
        max_active_per_parent,
        composed_task,
        handoff_included,
        idempotency_key: input.idempotency_key,
        normalized_intent,
        existing_agent,
        remote,
    })
}

/// What a worker is started with.
struct Launch {
    provider: se_types::Provider,
    harness: Option<String>,
    model: Option<String>,
    named_profile: String,
    permission: PermissionProfile,
    ttl_seconds: u32,
}

/// A new worker's launch from this machine's current configuration.
fn new_launch(
    input: &DelegateStart,
    configuration: &ConfigFile,
    allowlist: Option<AllowCheck>,
) -> Result<Launch> {
    let binding =
        crate::harness_selection::resolve(configuration, input.provider, input.harness.as_deref())?;
    let provider = binding.provider;
    let defaults = configuration.provider(provider);
    let named_profile = input
        .profile
        .clone()
        .unwrap_or_else(|| defaults.profile.clone());
    if let Some(allowed) = allowlist {
        allowed(&configuration.delegation, provider, &named_profile)?;
    }
    let resolved = configuration.resolve_profile(&named_profile, provider, true)?;
    let configured_ttl = configuration.delegation.ttl_seconds();
    Ok(Launch {
        provider,
        harness: binding.harness,
        model: input
            .model
            .clone()
            .or_else(|| (!defaults.model.is_empty()).then(|| defaults.model.clone())),
        named_profile,
        permission: match resolved.sandbox {
            EffectiveSandbox::ReadOnly => PermissionProfile::ReadOnly,
            EffectiveSandbox::WorkspaceWrite => PermissionProfile::WorkspaceWrite,
            EffectiveSandbox::Bypass => PermissionProfile::NamedFullBypass,
        },
        ttl_seconds: input
            .ttl_seconds
            .map_or(configured_ttl, |requested| requested.min(configured_ttl)),
    })
}

/// An existing worker's launch, exactly as its store saved it.
fn committed_launch<R: Snapshot>(agent: &AgentId, cx: &mut Cx<'_, R>) -> Result<Launch> {
    let saved = scope::require_present(
        cx.read
            .profile(agent.clone())
            .map_err(|error| store_error(&error))?,
        "delegated worker profile",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let EventBody::ProfileSaved { profile, .. } = saved.current.body else {
        return Err(scope::unreadable(
            "delegated worker profile",
            "the profile projection has the wrong event kind",
        ));
    };
    let record = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|error| store_error(&error))?,
        "delegated worker",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let EventBody::PrincipalRegistered {
        ephemeral: Some(spec),
        ..
    } = &record.original.as_deref().unwrap_or(&record.current).body
    else {
        return Err(scope::unreadable(
            "delegated worker",
            "the original registration is not a temporary agent",
        ));
    };
    Ok(Launch {
        provider: profile.provider.into(),
        harness: profile.harness,
        model: profile.model,
        named_profile: profile.named_profile,
        permission: profile.permission,
        ttl_seconds: spec.ttl_seconds,
    })
}

fn operation(remote: Option<&RemoteDelegation>) -> &'static str {
    match remote {
        Some(_) => "remote.delegate",
        None => "delegate.start",
    }
}

/// Build the atomic `PrincipalRegistered { ephemeral: Some(..) } + ProfileSaved`
/// batch for a qualified `DelegateStartPlan`, rechecking the active-child cap
/// on the fresh commit snapshot so concurrent requests cannot race past it.
pub fn create_ephemeral_batch<R: Snapshot>(
    kernel: &Kernel,
    plan: &DelegateStartPlan,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let operation = operation(plan.remote.as_ref());
    if find_replayed_agent(
        kernel,
        operation,
        &plan.idempotency_key,
        &plan.normalized_intent,
        cx,
    )?
    .is_none()
    {
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
            external: false,
        },
        expected: Expected::Absent,
    };
    let mut bodies = vec![identity, profile];
    if let Some(origin) = &plan.remote {
        bodies.push(EventBody::RemoteDelegateAttributed {
            record: se_store::remote::DelegateAttribution {
                anchor: origin.anchor.clone(),
                worker: plan.agent_id.clone(),
                attribution: origin.attribution.clone(),
            },
        });
    }
    process_commit::batch(
        kernel,
        operation,
        plan.idempotency_key.clone(),
        plan.normalized_intent.clone(),
        bodies,
        cx,
    )
}

/// Refuse when this parent already has `cap` active temporary children: a
/// local parent's in its project, a remote machine's across this whole store.
pub fn enforce_active_child_cap<R: Snapshot>(cap: u32, cx: &mut Cx<'_, R>) -> Result<()> {
    if let Actor::Remote(_) = &cx.admission.actor {
        let active = cx
            .read
            .remote_active_workers()
            .map_err(|error| store_error(&error))?;
        return if active >= cap {
            Err(over_cap(active, cap, &cx.admission.actor))
        } else {
            Ok(())
        };
    }
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
                    return Err(over_cap(active_children, cap, &cx.admission.actor));
                }
            }
        }
        match next {
            Some(cursor) => after = Some(cursor),
            None => return Ok(()),
        }
    }
}

/// The cap refusal, with a step the caller can actually take.
fn over_cap(active: u32, cap: u32, actor: &Actor) -> SeError {
    let (subject, reason, next_step) = match actor {
        Actor::Remote(_) => (
            "remote.delegate",
            format!(
                "this paired machine already has {active} of its {cap} allowed active workers here"
            ),
            "Wait for one of its workers to finish its turn; the destination Owner can cancel one with se delegate cancel <agent>.",
        ),
        _ => (
            "delegate.start",
            format!("parent already has {active} active temporary agents (cap is {cap})"),
            "Wait for an active temporary agent to finish or cancel one with se delegate cancel <agent>.",
        ),
    };
    SeError::new(Detail::StateConflict(details::StateConflict {
        subject: subject.into(),
        reason,
        next_step: next_step.into(),
    }))
}

/// An agent caller is not itself temporary (depth 1) and holds its create grant.
pub(crate) fn require_delegate_authority<R: Snapshot>(op: &str, cx: &mut Cx<'_, R>) -> Result<()> {
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
                    subject: op.into(),
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
                op: format!(
                    "{op} without an active agent create grant (set via se config set agent.<name>.can-create true)"
                ),
            },
        ))),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => Err(scope::unreadable("delegate create grant", &what)),
    }
}

/// The worker an earlier request with this key created. The key is resolved
/// with its whole intent, so a different request reusing it is refused.
fn find_replayed_agent<R: Snapshot>(
    kernel: &Kernel,
    operation: &'static str,
    key: &IdempotencyKey,
    intent: &serde_json::Value,
    cx: &mut Cx<'_, R>,
) -> Result<Option<(AgentId, String)>> {
    let request = kernel.request_identity(operation, key.clone(), intent)?;
    match cx
        .read
        .resolve_request(&request)
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => committed_worker(&value, cx).map(Some),
        Read::Absent { .. } => Ok(None),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => Err(scope::unreadable("delegate idempotency", &what)),
    }
}

/// The worker a creation receipt committed, whichever request won the write.
pub fn committed_worker<R: Snapshot>(
    receipt: &se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<(AgentId, String)> {
    match receipt::committed_event(cx.read, receipt)?.body {
        EventBody::PrincipalRegistered {
            principal: Actor::Agent(agent),
            name,
            ..
        } => Ok((agent, name)),
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
