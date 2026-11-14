//! Delegate only the saved target's normal headless launch, retaining its origin.
use super::*;
use crate::{
    commit::Cx,
    dispatch::Kernel,
    ops::{
        agent_launch::{AgentLaunch, LaunchPlan},
        process_plan,
    },
};
use se_store::Snapshot;
use se_types::remote::RemoteLaunch;

pub fn launch_key(
    attribution: &RemoteAttribution,
    key: &se_types::IdempotencyKey,
) -> Result<se_types::IdempotencyKey> {
    let source = attribution.source.as_ref().map(|s| s.address());
    let intent = serde_json::to_vec(&("remote-launch/v1", source, key))
        .map_err(|_| scope::unreadable("remote launch key", "stable origin encoding failed"))?;
    se_types::IdempotencyKey::new(format!(
        "remote-launch-{}",
        se_types::hex_lower(&Sha256::digest(intent))
    ))
}

pub fn plan_launch<R: Snapshot>(
    admission: RemoteAdmission,
    input: RemoteLaunch,
    attribution: RemoteAttribution,
    kernel: &Kernel,
    configuration: &crate::config_policy::ConfigFile,
    cx: &mut Cx<'_, R>,
) -> Result<LaunchPlan> {
    if admission.verb != RemoteVerb::Launch
        || admission.targets.as_slice() != std::slice::from_ref(&input.target)
        || cx.admission.actor != Actor::Remote(admission.grant.principal.clone())
        || cx.admission.scope != Scope::Project(input.target.project.clone())
        || cx.admission.session.is_some()
        || attribution.grant != admission.grant.grant
        || attribution.principal != admission.grant.principal
    {
        return Err(scope::unreadable(
            "remote launch authority",
            "the native admission differs from this exact Owner-approved destination identity",
        ));
    }
    let request = AgentLaunch {
        target_agent_id: Some(input.target.agent),
        fresh: false,
        model: None,
        task: None,
        detach: true,
        override_live: false,
        force_selection: None,
        idempotency_key: launch_key(&attribution, &input.idempotency_key)?,
        owner_agent: None,
        owner_provider: None,
    };
    let mut plan = process_plan::launch(kernel, request, configuration, cx)?;
    if !plan.replayed && (!plan.control.processes.is_empty() || !plan.control.sessions.is_empty()) {
        return Err(se_types::SeError::new(se_types::Detail::CapabilityInvalid(se_types::details::CapabilityInvalid {
            subject:"remote launch".into(),reason:"the selected agent already has live or unresolved work; launch consent does not authorize stopping it".into(),
            next_step:"Use its current session from remote list, or ask the destination Owner to finish its existing lifecycle before starting it through pairing consent.".into(),
        })));
    }
    plan.remote = Some(attribution);
    Ok(plan)
}
