use super::*;
use se_types::remote::{RemoteScope, RemoteVerb};

fn next(c: &Connection, table: &str, column: &str, id: &str) -> StoreResult<u64> {
    let old: Option<i64> = c
        .query_row(
            &format!("SELECT revision FROM {table} WHERE {column}=?"),
            [key(id)?],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    u64::try_from(old.unwrap_or(0))
        .map_err(invalid)?
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| invalid("remote revision exhausted"))
}
pub(crate) fn revision(c: &Connection, event: &NewEvent) -> StoreResult<u64> {
    let EventBody::RemoteSecurity { transition } = &event.body else {
        return Err(invalid("remote revision dispatch"));
    };
    match transition {
        SecurityTransition::Connect { grant } => {
            next(c, "remote_grants", "grant_id", grant.grant.as_str())
        }
        SecurityTransition::Renew { grant, .. } | SecurityTransition::Revoke { grant, .. } => {
            next(c, "remote_grants", "grant_id", grant.as_str())
        }
        SecurityTransition::LaunchPermission { change } => {
            launch_permission::revision(c, &change.grant, &change.target)
        }
        SecurityTransition::RevokeAll => Ok(1),
    }
}
fn scope(c: &Connection, scope: &RemoteScope) -> StoreResult<()> {
    if scope.targets.len() > 64 || scope.verbs.is_empty() || scope.verbs.len() > 3 {
        return Err(invalid("remote scope cardinality"));
    }
    let mut targets = std::collections::HashSet::new();
    for t in &scope.targets {
        if !targets.insert((t.project.as_str(), t.agent.as_str())) {
            return Err(invalid("duplicate remote target"));
        }
        let project = crate::identity::key(c, "project", t.project.as_str(), &[0], false)?;
        let mut namespace = vec![1];
        namespace.extend_from_slice(&project);
        let agent = crate::identity::key(c, "agent", t.agent.as_str(), &namespace, false)?;
        let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM principals a JOIN projects p USING(project_id) WHERE a.project_id=? AND a.principal_id=? AND a.principal_kind='agent' AND p.state='active')",rusqlite::params![project,agent],|r|r.get(0)).map_err(sql)?;
        if !exists {
            return Err(denied());
        }
    }
    let mut seen = std::collections::HashSet::new();
    for verb in &scope.verbs {
        let name = match verb {
            RemoteVerb::List => "list",
            RemoteVerb::Watch => "watch",
            RemoteVerb::Send => "send",
        };
        if !seen.insert(name) {
            return Err(invalid("duplicate remote verb"));
        }
    }
    Ok(())
}
fn owner(c: &Connection, h: &EventHeader) -> StoreResult<()> {
    let Actor::Human(id) = &h.actor else {
        return Err(denied());
    };
    if h.scope != Scope::Registry || h.session.is_some() || h.door == Door::Import {
        return Err(denied());
    }
    let human = crate::identity::key(c, "human", id.as_str(), &[0], false)?;
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM owners WHERE human_id=?)",
            [human],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !exists {
        return Err(denied());
    }
    Ok(())
}
pub(crate) fn apply(
    c: &Connection,
    h: &EventHeader,
    transition: SecurityTransition,
    seq: i64,
    revision: u64,
) -> StoreResult<()> {
    let info = crate::connection::info(c)?;
    ready(&info)?;
    let recorded: i64 = c
        .query_row(
            "SELECT recorded_at_us FROM events WHERE seq=?",
            [seq],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !matches!(&transition, SecurityTransition::Renew { .. }) {
        owner(c, h)?;
    }
    match transition {
        SecurityTransition::Connect { grant: g } => {
            scope(c, &g.scope)?;
            if g.store != info.id
                || revision != 1
                || g.authority_revision.value.get() != 1
                || g.lease_revision.value.get() != 1
                || g.state != GrantState::Active
                || !matches!(g.subject, se_types::remote::RemoteSubject::Machine { .. })
                || g.issued_at_us > recorded
                || g.last_use_at_us != g.issued_at_us
                || g.expires_at_us.checked_sub(g.last_use_at_us) != Some(GRANT_INACTIVITY_US)
                || g.expires_at_us <= recorded
                || g.credential_sha256.0 == [0; 32]
            {
                return Err(invalid("remote initial machine session"));
            }
            let grant_key = key(g.grant.as_str())?;
            c.execute("INSERT INTO remote_grants(grant_id,principal_id,device_id,credential_sha256,host,store_id,subject,scope,issued_at_us,authority_revision,state,last_use_at_us,expires_at_us,lease_revision,revision,last_seq) VALUES(?,?,?,?,?,?,?,?,?,1,'active',?,?,1,1,?)",rusqlite::params![grant_key,key(g.principal.as_str())?,key(g.device.as_str())?,encode(&g.credential_sha256)?,encode(&g.host)?,key(g.store.as_str())?,encode(&g.subject)?,encode(&g.scope)?,g.issued_at_us,g.last_use_at_us,g.expires_at_us,seq]).map_err(sql)?;
        }
        SecurityTransition::Renew {
            grant,
            authority_revision,
            expected_lease_revision,
            proven_use_at_us,
        } => {
            let g = read::grant(c, &grant)?.ok_or_else(denied)?;
            if h.scope != Scope::Registry
                || h.session.is_some()
                || h.actor != Actor::Remote(g.principal)
                || proven_use_at_us > recorded
                || proven_use_at_us
                    .checked_sub(g.last_use_at_us)
                    .is_none_or(|age| age < LEASE_COALESCE_US)
            {
                return Err(denied());
            }
            let expiry = proven_use_at_us
                .checked_add(GRANT_INACTIVITY_US)
                .ok_or_else(|| invalid("lease expiry overflow"))?;
            let n=c.execute("UPDATE remote_grants SET last_use_at_us=?,expires_at_us=?,lease_revision=lease_revision+1,revision=revision+1,last_seq=? WHERE grant_id=? AND state='active' AND expires_at_us>? AND authority_revision=? AND lease_revision=?",rusqlite::params![proven_use_at_us,expiry,seq,key(grant.as_str())?,recorded,i64::try_from(authority_revision.value.get()).map_err(invalid)?,i64::try_from(expected_lease_revision.value.get()).map_err(invalid)?]).map_err(sql)?;
            if n != 1 {
                return Err(denied());
            }
        }
        SecurityTransition::Revoke { grant, expected } => {
            let n=c.execute("UPDATE remote_grants SET state='revoked',authority_revision=authority_revision+1,revision=revision+1,last_seq=? WHERE grant_id=? AND state='active' AND authority_revision=?",rusqlite::params![seq,key(grant.as_str())?,i64::try_from(expected.value.get()).map_err(invalid)?]).map_err(sql)?;
            if n != 1 {
                return Err(denied());
            }
        }
        SecurityTransition::LaunchPermission { change } => {
            launch_permission::apply(c, change, seq, revision, recorded)?
        }
        SecurityTransition::RevokeAll => {
            c.execute("UPDATE remote_grants SET state='revoked',authority_revision=authority_revision+1,revision=revision+1,last_seq=? WHERE state='active'",[seq]).map_err(sql)?;
        }
    }
    Ok(())
}
