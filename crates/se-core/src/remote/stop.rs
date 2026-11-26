//! Stop only a session this paired principal launched, through native custody.
use super::*;
use crate::{
    commit::Cx,
    ops::{
        AgentStop,
        stop_plan::{self, ExpectedLifecycle, StopPlan},
    },
};
use se_store::{Snapshot, remote::LaunchAttribution};
use se_types::remote::RemoteStop;

/// A remote stop key is scoped to its authenticated origin, like launch.
pub fn stop_key(
    attribution: &RemoteAttribution,
    key: &se_types::IdempotencyKey,
) -> Result<se_types::IdempotencyKey> {
    let source = attribution.source.as_ref().map(|s| s.address());
    let intent = serde_json::to_vec(&("remote-stop/v1", source, key))
        .map_err(|_| scope::unreadable("remote stop key", "stable origin encoding failed"))?;
    se_types::IdempotencyKey::new(format!(
        "remote-stop-{}",
        se_types::hex_lower(&Sha256::digest(intent))
    ))
}

/// Stop needs no scope verb or launch consent: the recorded launch is the
/// authority, so a pairing whose launch consent was withdrawn can still stop.
pub fn authorize_stop(
    grant: GrantRecord,
    input: &RemoteStop,
    launched: se_types::Read<LaunchAttribution>,
    now: i64,
) -> Result<RemoteAdmission> {
    if grant.state != GrantState::Active || grant.expires_at_us <= now {
        return Err(scope::unreadable(
            "remote grant",
            "machine session is expired or revoked; the machine owner can explicitly reconnect with se remote add",
        ));
    }
    let foreign = |reason: String| {
        se_types::SeError::new(se_types::Detail::CapabilityInvalid(
            se_types::details::CapabilityInvalid {
                subject: "remote stop".into(),
                reason,
                next_step: "Stop only sessions returned by your own remote launch. For other work, ask the destination Owner to run se stop AGENT in a terminal on that machine.".into(),
            },
        ))
    };
    let launched = match launched {
        se_types::Read::Present { value } => value,
        se_types::Read::Absent { checked } => return Err(foreign(checked)),
        se_types::Read::Unknown { what } => return Err(foreign(what)),
        se_types::Read::Unreadable { reason, .. } => {
            return Err(scope::unreadable("remote launch record", &reason));
        }
    };
    if launched.target != input.target
        || launched.session != input.session
        || launched.attribution.principal != grant.principal
    {
        return Err(foreign(
            "the recorded launch differs from this exact target and session".into(),
        ));
    }
    grant.scope.validate()?;
    Ok(RemoteAdmission {
        grant,
        verb: RemoteVerb::Stop,
        targets: vec![input.target.clone()],
        launched: Some(launched),
    })
}

pub fn plan_stop<R: Snapshot>(
    admission: RemoteAdmission,
    input: RemoteStop,
    attribution: &RemoteAttribution,
    cx: &mut Cx<'_, R>,
) -> Result<StopPlan> {
    let launched = admission.launched.as_ref().ok_or_else(|| {
        scope::unreadable("remote stop authority", "the recorded launch is absent")
    })?;
    if admission.verb != RemoteVerb::Stop
        || admission.targets.as_slice() != std::slice::from_ref(&input.target)
        || launched.target != input.target
        || launched.session != input.session
        || cx.admission.actor != Actor::Remote(admission.grant.principal.clone())
        || cx.admission.scope != Scope::Project(input.target.project.clone())
        || cx.admission.session.is_some()
        || attribution.grant != admission.grant.grant
        || attribution.principal != admission.grant.principal
    {
        return Err(scope::unreadable(
            "remote stop authority",
            "the native admission differs from this exact recorded launch",
        ));
    }
    let expected = ExpectedLifecycle {
        session: launched.session.clone(),
        lifecycle: launched.lifecycle.clone(),
    };
    let projects = stop_plan::projects(cx)?;
    let project = projects
        .first()
        .filter(|_| projects.len() == 1)
        .ok_or_else(|| se_types::SeError::invalid("remote stop project", "one project"))?
        .clone();
    let mut target = stop_plan::control(project.clone(), input.target.agent.clone(), cx)?;
    expected.check(&target.control)?;
    target.expected = Some(expected);
    Ok(StopPlan {
        input: AgentStop {
            target_agent_id: Some(input.target.agent),
            idempotency_key: stop_key(attribution, &input.idempotency_key)?,
            owner_agent: None,
            all: false,
            release: false,
        },
        projects: vec![project],
        targets: vec![target],
    })
}
