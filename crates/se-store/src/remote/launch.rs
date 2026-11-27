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
    if info.schema_version < 11 {
        return if records.is_empty() {
            Ok(false)
        } else {
            Err(denied())
        };
    }
    if records.is_empty() {
        return super::launch_continue::validate(c, batch);
    }
    if records.len() != 1
        || batch.request.is_none()
        || !matches!(
            batch.events.last().map(|event| &event.body),
            Some(EventBody::RemoteLaunchAttributed { .. })
        )
    {
        return Err(denied());
    }
    let record = records[0];
    // A delegated worker starts under its anchor's consent, never its own.
    let consent = record.delegated_from.as_ref().unwrap_or(&record.target);
    let grant = consented(c, batch, info, now, &record.attribution, consent)?;
    if let Some(anchor) = &record.delegated_from {
        super::delegate::require_worker(c, info, &grant, anchor, &record.target)?;
    }
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
            "the saved launch profile changed before native creation; review the updated profile with se remote permissions --name <saved-alias> --launch in a terminal, then submit a new launch key",
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

/// The grant behind `stamp` is current, matches this batch's admission, and
/// holds the Owner's launch consent for `consent` in the admitted project.
pub(super) fn consented(
    c: &Connection,
    batch: &AtomicBatch,
    info: &StoreInfo,
    now: i64,
    stamp: &se_types::remote::RemoteAttribution,
    consent: &se_types::remote::RemoteTarget,
) -> StoreResult<GrantRecord> {
    let grant = read::grant(c, &stamp.grant)?.ok_or_else(denied)?;
    let permission = launch_permission::permission(c, &grant.grant, consent)?.ok_or_else(denied)?;
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
        || batch.admission.actor != Actor::Remote(grant.principal.clone())
        || batch.admission.session.is_some()
        || batch.admission.scope != Scope::Project(consent.project.clone())
    {
        return Err(denied());
    }
    Ok(grant)
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
    if launch_permission::permission(c, grant, target)?.is_some_and(|p| p.allowed)
        || super::delegate::created_by_grant(c, grant, target)?
    {
        return Ok(true);
    }
    let p = crate::identity::key(c, "project", target.project.as_str(), &[0], false)?;
    let scope = crate::identity::scope_key(c, &Scope::Project(target.project.clone()), false)?;
    let a = crate::identity::key(c, "agent", target.agent.as_str(), &scope, false)?;
    c.query_row("SELECT EXISTS(SELECT 1 FROM remote_launch_attribution WHERE grant_id=? AND project_id=? AND agent_id=?)",
        rusqlite::params![key(grant.as_str())?,p,a],|r|r.get(0)).map_err(sql)
}

impl ReadPhase {
    /// A paired principal's own launch of one session: the only authority for
    /// remote stop, or why none exists. Uses the same principal join as the store's continuation check.
    pub fn remote_launched_session(
        &self,
        principal: &se_types::RemotePrincipalId,
        target: &se_types::remote::RemoteTarget,
        session: &se_types::SessionId,
    ) -> StoreResult<se_types::Read<LaunchAttribution>> {
        ready(&self.info)?;
        if self.info.schema_version < 11 {
            return Ok(se_types::Read::Absent {
                checked: "this store predates recorded remote launches".into(),
            });
        }
        let Some(session_key) = crate::identity::canonical(session.as_str()) else {
            return Ok(se_types::Read::Absent {
                checked: "remote launches record only canonical session IDs".into(),
            });
        };
        let project =
            crate::identity::key(&self.db, "project", target.project.as_str(), &[0], false)?;
        let scope =
            crate::identity::scope_key(&self.db, &Scope::Project(target.project.clone()), false)?;
        let agent = crate::identity::key(&self.db, "agent", target.agent.as_str(), &scope, false)?;
        let facts: Option<String> = self
            .db
            .query_row(
                "SELECT a.facts FROM remote_launch_attribution a JOIN remote_grants g ON g.grant_id=a.grant_id WHERE g.principal_id=? AND a.project_id=? AND a.agent_id=? AND a.session_id=?",
                rusqlite::params![key(principal.as_str())?, project, agent, session_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        Ok(match facts {
            Some(facts) => se_types::Read::Present {
                value: decode(facts)?,
            },
            None => se_types::Read::Absent {
                checked: "this paired machine did not launch that session of that agent".into(),
            },
        })
    }
}
