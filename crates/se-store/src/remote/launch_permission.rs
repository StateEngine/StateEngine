//! Native Owner consent for one paired machine and one saved destination agent.
use super::*;
use se_types::{Read, remote::*};

pub(super) fn permission(
    c: &Connection,
    grant: &RemoteGrantId,
    target: &RemoteTarget,
) -> StoreResult<Option<LaunchPermission>> {
    c.query_row(
        "SELECT allowed,revision FROM remote_launch_permissions WHERE grant_id=? AND target=?",
        rusqlite::params![key(grant.as_str())?, encode(target)?],
        |r| Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?)),
    )
    .optional()
    .map_err(sql)?
    .map(|(allowed, revision)| {
        Ok(LaunchPermission {
            grant: grant.clone(),
            target: target.clone(),
            allowed,
            revision: crate::codec::revision(u64::try_from(revision).map_err(invalid)?)?,
        })
    })
    .transpose()
}

pub(super) fn revision(
    c: &Connection,
    grant: &RemoteGrantId,
    target: &RemoteTarget,
) -> StoreResult<u64> {
    permission(c, grant, target)?.map_or(Ok(1), |record| {
        record
            .revision
            .value
            .get()
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or_else(|| invalid("launch permission revision exhausted"))
    })
}

pub(super) fn apply(
    c: &Connection,
    change: LaunchPermissionChange,
    seq: i64,
    revision: u64,
    now: i64,
) -> StoreResult<()> {
    if crate::connection::info(c)?.schema_version < 12
        || permission(c, &change.grant, &change.target)?.map(|p| p.revision) != change.expected
    {
        return Err(denied());
    }
    let grant = read::grant(c, &change.grant)?.ok_or_else(denied)?;
    if change.allowed {
        if grant.state != GrantState::Active || grant.expires_at_us <= now {
            return Err(denied());
        }
        require_saved_target(c, &change.target)?;
    }
    c.execute("INSERT INTO remote_launch_permissions(grant_id,target,allowed,revision,last_seq) VALUES(?,?,?,?,?) ON CONFLICT(grant_id,target) DO UPDATE SET allowed=excluded.allowed,revision=excluded.revision,last_seq=excluded.last_seq",
        rusqlite::params![key(change.grant.as_str())?,encode(&change.target)?,change.allowed,i64::try_from(revision).map_err(invalid)?,seq]).map_err(sql)?;
    Ok(())
}

pub(super) fn require_saved_target(c: &Connection, target: &RemoteTarget) -> StoreResult<()> {
    let project = crate::identity::key(c, "project", target.project.as_str(), &[0], false)?;
    let scope = crate::identity::scope_key(c, &Scope::Project(target.project.clone()), false)?;
    let agent = crate::identity::key(c, "agent", target.agent.as_str(), &scope, false)?;
    let known:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM principals a JOIN projects p USING(project_id) JOIN profiles f ON f.project_id=a.project_id AND f.agent_id=a.principal_id WHERE a.project_id=? AND a.principal_id=? AND a.principal_kind='agent' AND p.state='active')",
        rusqlite::params![project,agent],|r|r.get(0)).map_err(sql)?;
    if !known {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "launch requires an existing destination agent with a saved profile in an active project; its Owner must choose it with se remote permissions --name <saved-alias> --launch in a terminal",
        ));
    }
    Ok(())
}

impl ReadPhase {
    pub fn remote_launch_permission(
        &self,
        grant: &RemoteGrantId,
        target: &RemoteTarget,
    ) -> StoreResult<Read<LaunchPermission>> {
        ready(&self.info)?;
        if self.info.schema_version < 12 {
            return Ok(Read::Absent {
                checked: "this store predates explicit remote launch consent".into(),
            });
        }
        Ok(match permission(&self.db, grant, target)? {
            Some(value) => Read::Present { value },
            None => Read::Absent {
                checked:
                    "the Owner has not allowed this paired machine to launch this destination agent"
                        .into(),
            },
        })
    }
}
