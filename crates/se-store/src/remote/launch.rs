//! Fresh Owner consent precedes native creation; C1 records the accepted lifecycle.
use super::*;

pub(crate) fn validate_launch(
    c: &Connection,
    batch: &AtomicBatch,
    info: &StoreInfo,
    now: i64,
) -> StoreResult<bool> {
    let records: Vec<_> = batch
        .events
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::RemoteLaunchAttributed { record } => Some(record),
            _ => None,
        })
        .collect();
    if info.schema_version < 12 {
        return if records.is_empty() {
            Ok(false)
        } else {
            Err(denied())
        };
    }
    if records.is_empty() {
        return super::launch_continue::validate(c, batch);
    }
    if records.len() != 1 || info.schema_version < 12 || batch.request.is_none() {
        return Err(denied());
    }
    let record = records[0];
    let stamp = &record.attribution;
    let grant = read::grant(c, &stamp.grant)?.ok_or_else(denied)?;
    let permission =
        launch_permission::permission(c, &grant.grant, &record.target)?.ok_or_else(denied)?;
    if !permission.allowed
        || grant.state != GrantState::Active
        || grant.expires_at_us <= now
        || grant.store != info.id
        || stamp.store != info.id
        || stamp.host != grant.host
        || stamp.principal != grant.principal
        || stamp.device != grant.device
        || stamp.authority_revision != grant.authority_revision.value.get()
        || !grant.subject.admits_source(stamp.source.as_ref())
        || batch.admission.actor != Actor::Remote(grant.principal)
        || batch.admission.session.is_some()
        || batch.admission.scope != Scope::Project(record.target.project.clone())
    {
        return Err(denied());
    }
    super::admit_source(c, stamp.source.as_ref())?;
    launch_permission::require_saved_target(c, &record.target)?;
    let project = crate::identity::key(c, "project", record.target.project.as_str(), &[0], false)?;
    let namespace =
        crate::identity::scope_key(c, &Scope::Project(record.target.project.clone()), false)?;
    let agent = crate::identity::key(c, "agent", record.target.agent.as_str(), &namespace, false)?;
    let profile: i64 = c
        .query_row(
            "SELECT revision FROM profiles WHERE project_id=? AND agent_id=?",
            rusqlite::params![project, agent],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if u64::try_from(profile).ok() != Some(record.expected_profile.value.get()) {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            "the saved launch profile changed before native creation; reread pairing metadata and retry the original launch key",
        ));
    }
    let mut sessions = 0;
    let mut processes = 0;
    for event in &batch.events {
        if event.header.door != Door::Host {
            return Err(denied());
        }
        match &event.body {
            EventBody::SessionPrepared { session, agent, .. }
                if session == &record.session && agent == &record.target.agent =>
            {
                sessions += 1
            }
            EventBody::ProcessRegistered { identity, .. }
                if identity.record == record.lifecycle
                    && identity.principal == Actor::Agent(record.target.agent.clone())
                    && identity.session.as_ref() == Some(&record.session) =>
            {
                processes += 1
            }
            EventBody::CredentialIssued { session, .. } if session == &record.session => (),
            EventBody::RemoteLaunchAttributed { .. } => (),
            _ => return Err(denied()),
        }
    }
    if sessions != 1 || processes != 1 {
        return Err(denied());
    }
    Ok(true)
}

pub(crate) fn apply(
    c: &Connection,
    h: &EventHeader,
    record: LaunchAttribution,
    seq: i64,
) -> StoreResult<()> {
    if h.door != Door::Host
        || h.actor != Actor::Remote(record.attribution.principal.clone())
        || h.session.is_some()
        || h.scope != Scope::Project(record.target.project.clone())
    {
        return Err(denied());
    }
    let p = crate::identity::key(c, "project", record.target.project.as_str(), &[0], false)?;
    let scope = crate::identity::scope_key(c, &h.scope, false)?;
    let a = crate::identity::key(c, "agent", record.target.agent.as_str(), &scope, false)?;
    let session = key(record.session.as_str())?;
    let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND agent_id=? AND session_id=?)",
        rusqlite::params![p,a,session],|r|r.get(0)).map_err(sql)?;
    if !valid {
        return Err(denied());
    }
    c.execute("INSERT INTO remote_launch_attribution(project_id,agent_id,session_id,lifecycle_id,grant_id,facts,event_seq) VALUES(?,?,?,?,?,?,?)",
        rusqlite::params![p,a,session,key(record.lifecycle.as_str())?,key(record.attribution.grant.as_str())?,encode(&record)?,seq]).map_err(sql)?;
    Ok(())
}

pub(crate) fn target_owned(
    c: &Connection,
    grant: &se_types::RemoteGrantId,
    target: &se_types::remote::RemoteTarget,
) -> StoreResult<bool> {
    if launch_permission::permission(c, grant, target)?.is_some_and(|p| p.allowed) {
        return Ok(true);
    }
    let p = crate::identity::key(c, "project", target.project.as_str(), &[0], false)?;
    let scope = crate::identity::scope_key(c, &Scope::Project(target.project.clone()), false)?;
    let a = crate::identity::key(c, "agent", target.agent.as_str(), &scope, false)?;
    c.query_row("SELECT EXISTS(SELECT 1 FROM remote_launch_attribution WHERE grant_id=? AND project_id=? AND agent_id=?)",
        rusqlite::params![key(grant.as_str())?,p,a],|r|r.get(0)).map_err(sql)
}
