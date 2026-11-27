//! Remote delegation is admitted twice, by each machine's own policy. The
//! source checks its caller before any network call; the destination checks
//! the anchor's consent, its own allowlist, and the anchor's profile ceiling.
use super::*;
use crate::{
    commit::Cx,
    dispatch::Kernel,
    ops::delegate::{
        DelegateStart, DelegateStartPlan, RemoteDelegation, RemoteRequest, Requester, plan_worker,
        require_delegate_authority,
    },
    store_error::store_error,
};
use se_config::config_policy::ConfigFile;
use se_store::{PermissionProfile, Snapshot};
use se_types::{
    AgentId, Detail, SeError, details,
    remote::{RemoteDelegate, RemoteDelegateWorker},
};

/// The source machine's policy, applied before the request leaves it: a
/// temporary agent cannot delegate (depth 1), an agent needs its create grant
/// and an explicit pair from this machine's `[delegation].allow`, and every
/// lifetime is lowered to this machine's cap.
pub fn admit_source_delegate<R: Snapshot>(
    configuration: Option<&ConfigFile>,
    request: &mut RemoteDelegate,
    cx: &mut Cx<'_, R>,
) -> Result<()> {
    request.validate()?;
    let configuration = configuration.ok_or_else(|| {
        scope::unreadable(
            "remote delegation policy",
            "this host has no bound configuration; restart it with se up",
        )
    })?;
    match &cx.admission.actor {
        Actor::Agent(_) => {
            require_delegate_authority("remote.delegate", cx)?;
            let (Some(provider), Some(profile)) = (request.provider, request.profile.as_deref())
            else {
                return Err(SeError::invalid(
                    "remote delegate provider and profile",
                    "both named, so this machine's [delegation].allow can check the pair; ask the Owner which pair is allowed",
                ));
            };
            configuration
                .delegation
                .require_allowed(provider, profile)?;
        }
        Actor::Human(_) => (),
        Actor::Remote(_) | Actor::Guest => {
            return Err(SeError::invalid(
                "remote delegate caller",
                "a local Owner terminal or a launched agent session",
            ));
        }
    }
    let cap = configuration.delegation.ttl_seconds();
    request.ttl_seconds = Some(request.ttl_seconds.map_or(cap, |ttl| ttl.min(cap)));
    Ok(())
}

/// The original remote key, scoped to its authenticated origin.
pub fn delegate_key(
    attribution: &RemoteAttribution,
    key: &se_types::IdempotencyKey,
) -> Result<se_types::IdempotencyKey> {
    let source = attribution.source.as_ref().map(|s| s.address());
    let intent = serde_json::to_vec(&("remote-delegate/v1", source, key))
        .map_err(|_| scope::unreadable("remote delegate key", "stable origin encoding failed"))?;
    se_types::IdempotencyKey::new(format!(
        "remote-delegate-{}",
        se_types::hex_lower(&Sha256::digest(intent))
    ))
}

/// Destination admission. The anchor is a saved, non-temporary agent this
/// grant may launch; the worker's pair must be in the destination's own
/// `[delegation].remote_allow`, and its permission may not exceed the anchor's.
pub fn plan_delegate<R: Snapshot>(
    admission: RemoteAdmission,
    input: RemoteDelegate,
    attribution: RemoteAttribution,
    kernel: &Kernel,
    configuration: &ConfigFile,
    cx: &mut Cx<'_, R>,
) -> Result<DelegateStartPlan> {
    if admission.verb != RemoteVerb::Launch
        || admission.targets.as_slice() != std::slice::from_ref(&input.target)
        || cx.admission.actor != Actor::Remote(admission.grant.principal.clone())
        || cx.admission.scope != Scope::Project(input.target.project.clone())
        || cx.admission.session.is_some()
        || attribution.grant != admission.grant.grant
        || attribution.principal != admission.grant.principal
    {
        return Err(scope::unreadable(
            "remote delegate authority",
            "the native admission differs from this exact Owner-approved destination identity",
        ));
    }
    input.validate()?;
    configuration.validate()?;
    let supplied = serde_json::to_value(&input)
        .map_err(|error| scope::unreadable("remote delegate intent", &error.to_string()))?;
    let anchor = &input.target;
    if ephemeral_ttl(cx, &anchor.agent)?.is_some() {
        return Err(SeError::new(Detail::StateConflict(details::StateConflict {
            subject: "remote delegate".into(),
            reason: "a temporary agent cannot anchor delegation (depth limit is 1)".into(),
            next_step: "Ask the destination Owner to allow a saved agent with se remote permissions --name <saved-alias> --launch in a terminal.".into(),
        })));
    }
    let saved = saved_profile(cx, &anchor.agent)?;
    let request = DelegateStart {
        task: input.task,
        role: input.role,
        provider: Some(input.provider.unwrap_or(saved.provider.into())),
        harness: None,
        model: None,
        profile: input
            .profile
            .or_else(|| (!saved.named_profile.is_empty()).then(|| saved.named_profile.clone())),
        handoff: None,
        ttl_seconds: input.ttl_seconds,
        idempotency_key: delegate_key(&attribution, &input.idempotency_key)?,
    };
    let origin = RemoteDelegation {
        anchor: anchor.clone(),
        attribution,
    };
    let plan = plan_worker(
        kernel,
        request,
        configuration,
        Requester::Remote(Box::new(RemoteRequest { origin, supplied })),
        cx,
    )?;
    // A retry continues its committed worker; the store rechecks that worker
    // against the anchor's current ceiling at its first launch.
    if plan.existing_agent.is_none()
        && (plan.permission == PermissionProfile::NamedFullBypass
            || rank(plan.permission) > rank(saved.permission))
    {
        return Err(SeError::new(Detail::ConfigurationInvalid(
            details::ConfigurationInvalid {
                subject: "remote delegate profile".into(),
                reason: format!(
                    "'{}' grants more than the anchor's saved profile, or full bypass",
                    plan.named_profile
                ),
                next_step: "Choose a profile no broader than the anchor's from the destination's [delegation].remote_allow.".into(),
            },
        )));
    }
    Ok(plan)
}

/// The worker as its store saved it, whichever request created it.
pub fn saved_worker<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    anchor: &RemoteTarget,
    agent: &AgentId,
    name: &str,
) -> Result<RemoteDelegateWorker> {
    let ttl_seconds = ephemeral_ttl(cx, agent)?.ok_or_else(|| {
        scope::unreadable(
            "remote delegate worker",
            "the original registration is not a temporary agent",
        )
    })?;
    let profile = saved_profile(cx, agent)?;
    Ok(RemoteDelegateWorker {
        anchor: anchor.clone(),
        name: name.to_owned(),
        provider: profile.provider.into(),
        profile: profile.named_profile,
        ttl_seconds,
    })
}

fn ephemeral_ttl<R: Snapshot>(cx: &mut Cx<'_, R>, agent: &AgentId) -> Result<Option<u32>> {
    let record = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|e| store_error(&e))?,
        "remote delegate agent",
        "Ask the destination Owner to choose a saved agent with se remote permissions --name <saved-alias> --launch in a terminal.",
    )?;
    match &record.original.as_deref().unwrap_or(&record.current).body {
        EventBody::PrincipalRegistered { ephemeral, .. } => {
            Ok(ephemeral.map(|spec| spec.ttl_seconds))
        }
        _ => Err(scope::unreadable(
            "remote delegate agent",
            "the original registration is unavailable",
        )),
    }
}

fn saved_profile<R: Snapshot>(cx: &mut Cx<'_, R>, agent: &AgentId) -> Result<se_store::Profile> {
    let record = scope::require_present(
        cx.read
            .profile(agent.clone())
            .map_err(|e| store_error(&e))?,
        "remote delegate saved profile",
        "Ask the destination Owner to save a launch profile for this agent with se agent add or se config.",
    )?;
    match record.current.body {
        EventBody::ProfileSaved { profile, .. } => Ok(profile),
        _ => Err(scope::unreadable(
            "remote delegate saved profile",
            "wrong immutable profile event",
        )),
    }
}

fn rank(permission: PermissionProfile) -> u8 {
    match permission {
        PermissionProfile::ReadOnly => 0,
        PermissionProfile::WorkspaceWrite => 1,
        PermissionProfile::NamedFullBypass => 2,
    }
}
