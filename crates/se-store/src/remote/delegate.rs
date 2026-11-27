//! A remote caller may create one temporary worker under an approved agent's
//! launch consent. The worker is one-shot, bounded, attributed to the caller,
//! and never holds more permission than its anchor's saved profile.
use super::*;
use se_types::{AgentId, remote::RemoteTarget};

/// The closed create batch: worker registration, its profile, then the
/// attribution naming the anchor whose consent admits it.
pub(crate) fn validate_create(
    c: &Connection,
    batch: &AtomicBatch,
    info: &StoreInfo,
    now: i64,
) -> StoreResult<bool> {
    let Some(EventBody::RemoteDelegateAttributed { record }) =
        batch.events.last().map(|event| &event.body)
    else {
        if batch
            .events
            .iter()
            .any(|e| matches!(e.body, EventBody::RemoteDelegateAttributed { .. }))
        {
            return Err(denied());
        }
        return Ok(false);
    };
    if info.schema_version < 17 || batch.request.is_none() || batch.events.len() != 3 {
        return Err(denied());
    }
    super::launch::consented(c, batch, info, now, &record.attribution, &record.anchor)?;
    launch_permission::require_saved_target(c, &record.anchor)?;
    let anchor = principal_key(c, &record.anchor.project, &record.anchor.agent)?;
    let (ephemeral, retired, anchor_owner): (bool, bool, Vec<u8>) = c
        .query_row(
            "SELECT ephemeral_one_shot IS NOT NULL AND ephemeral_one_shot!=0, retired_seq IS NOT NULL, owner_id FROM principals WHERE project_id=? AND principal_id=?",
            rusqlite::params![anchor.0, anchor.1],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(sql)?;
    if ephemeral || retired {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "a temporary or retired agent cannot anchor remote delegation; its Owner must allow a saved agent with se remote permissions --name <saved-alias> --launch in a terminal",
        ));
    }
    let creator = Actor::Agent(record.anchor.agent.clone());
    let worker = Actor::Agent(record.worker.clone());
    let [registered, profile, _] = batch.events.as_slice() else {
        return Err(denied());
    };
    let EventBody::PrincipalRegistered {
        principal,
        kind: PrincipalKind::Agent,
        owner,
        created_by: Some(by),
        ephemeral:
            Some(EphemeralSpec {
                one_shot: true,
                ttl_seconds,
            }),
        expected: Expected::Absent,
        ..
    } = &registered.body
    else {
        return Err(denied());
    };
    // The worker belongs to its anchor's owner and names the anchor as creator.
    let registered_ok = *principal == worker
        && *by == creator
        && (1..=86_400).contains(ttl_seconds)
        && crate::identity::key(c, "human", owner.as_str(), &[0], false)? == anchor_owner;
    let EventBody::ProfileSaved {
        agent,
        profile: saved,
        expected: Expected::Absent,
    } = &profile.body
    else {
        return Err(denied());
    };
    if !registered_ok
        || *agent != record.worker
        || batch.events.iter().any(|e| e.header.door != Door::Host)
    {
        return Err(denied());
    }
    if rank(saved.permission) > rank(saved_permission(c, info, &record.anchor)?)
        || saved.permission == PermissionProfile::NamedFullBypass
    {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "a remote worker cannot hold more permission than its anchor's saved profile, and never full bypass; choose a narrower profile listed in the destination's [delegation].remote_allow",
        ));
    }
    Ok(true)
}

/// The validator has already checked the batch; this only refuses a marker
/// that reached the writer without its worker.
pub(crate) fn apply(
    c: &Connection,
    h: &EventHeader,
    record: &super::DelegateAttribution,
) -> StoreResult<()> {
    if h.door != Door::Host
        || h.actor != Actor::Remote(record.attribution.principal.clone())
        || h.session.is_some()
        || h.scope != Scope::Project(record.anchor.project.clone())
    {
        return Err(denied());
    }
    let (project, worker) = principal_key(c, &record.anchor.project, &record.worker)?;
    let created: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principals WHERE project_id=? AND principal_id=? AND created_by IS NOT NULL)",
            rusqlite::params![project, worker],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !created {
        return Err(denied());
    }
    Ok(())
}

/// A delegated worker's start: this grant's caller created the worker under
/// this anchor, it is still one-shot and live, and its saved profile is still
/// no broader than the anchor's current one, which the Owner may have narrowed.
pub(super) fn require_worker(
    c: &Connection,
    info: &StoreInfo,
    grant: &GrantRecord,
    anchor: &RemoteTarget,
    worker: &RemoteTarget,
) -> StoreResult<()> {
    if anchor.project != worker.project || anchor.agent == worker.agent {
        return Err(denied());
    }
    if !created_by_grant(c, &grant.grant, worker)? {
        return Err(denied());
    }
    let (project, agent) = principal_key(c, &worker.project, &worker.agent)?;
    let (_, anchor_key) = principal_key(c, &anchor.project, &anchor.agent)?;
    let (live, creator): (bool, Option<Vec<u8>>) = c
        .query_row(
            "SELECT ephemeral_one_shot=1 AND retired_seq IS NULL, created_by FROM principals WHERE project_id=? AND principal_id=?",
            rusqlite::params![project, agent],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql)?;
    if !live || creator.as_deref() != Some(anchor_key.as_slice()) {
        return Err(denied());
    }
    let ceiling = saved_permission(c, info, anchor)?;
    let permission = saved_permission(c, info, worker)?;
    if permission == PermissionProfile::NamedFullBypass || rank(permission) > rank(ceiling) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "the anchor's saved profile is now narrower than this worker's, so the worker cannot start; send a new remote delegate request with a profile no broader than the anchor's",
        ));
    }
    Ok(())
}

/// Whether this grant's remote caller registered `target`. Only a validated
/// create batch registers an agent with a remote actor.
pub(crate) fn created_by_grant(
    c: &Connection,
    grant: &se_types::RemoteGrantId,
    target: &RemoteTarget,
) -> StoreResult<bool> {
    let Some(grant) = read::grant(c, grant)? else {
        return Ok(false);
    };
    let (project, agent) = principal_key(c, &target.project, &target.agent)?;
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM principals p JOIN events e ON e.seq=p.first_seq WHERE p.project_id=? AND p.principal_id=? AND p.principal_kind='agent' AND e.actor_id=?)",
        rusqlite::params![project, agent, key(grant.principal.as_str())?],
        |r| r.get(0),
    )
    .map_err(sql)
}

fn principal_key(
    c: &Connection,
    project: &se_types::ProjectId,
    agent: &AgentId,
) -> StoreResult<(Vec<u8>, Vec<u8>)> {
    let p = crate::identity::key(c, "project", project.as_str(), &[0], false)?;
    let scope = crate::identity::scope_key(c, &Scope::Project(project.clone()), false)?;
    let a = crate::identity::key(c, "agent", agent.as_str(), &scope, false)?;
    Ok((p, a))
}

/// The permission of `target`'s current saved profile.
fn saved_permission(
    c: &Connection,
    info: &StoreInfo,
    target: &RemoteTarget,
) -> StoreResult<PermissionProfile> {
    let (project, agent) = principal_key(c, &target.project, &target.agent)?;
    let seq: i64 = c
        .query_row(
            "SELECT last_seq FROM profiles WHERE project_id=? AND agent_id=?",
            rusqlite::params![project, agent],
            |r| r.get(0),
        )
        .map_err(sql)?;
    match crate::codec::event::load_event(c, seq, info)?.body {
        EventBody::ProfileSaved { profile, .. } => Ok(profile.permission),
        _ => Err(denied()),
    }
}

fn rank(permission: PermissionProfile) -> u8 {
    match permission {
        PermissionProfile::ReadOnly => 0,
        PermissionProfile::WorkspaceWrite => 1,
        PermissionProfile::NamedFullBypass => 2,
    }
}
