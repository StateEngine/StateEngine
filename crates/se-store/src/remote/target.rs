//! Exact target metadata only. No Owner/self identity is fabricated for remote reads.
use super::*;
use se_types::{Read, remote::*};
pub struct TargetFacts {
    pub target: RemoteTarget,
    pub project_name: String,
    pub principal: ProjectionRecord,
    pub profile: Read<ProjectionRecord>,
    pub session: Read<ProjectionRecord>,
    pub process: Read<ProjectionRecord>,
    pub pending: u64,
}
fn head(
    c: &Connection,
    info: &StoreInfo,
    row: Option<(i64, i64, i64)>,
) -> StoreResult<Read<ProjectionRecord>> {
    let Some((rev, seq, first)) = row else {
        return Ok(Read::Absent {
            checked: "exact granted target has no saved head".into(),
        });
    };
    Ok(Read::Present {
        value: ProjectionRecord {
            revision: crate::codec::revision(u64::try_from(rev).map_err(invalid)?)?,
            current: crate::read::load_event(c, seq, info)?,
            original: (first != seq)
                .then(|| crate::read::load_event(c, first, info).map(Box::new))
                .transpose()?,
        },
    })
}
impl ReadPhase {
    /// The grant, scope and target are rechecked on this same finite pin.
    pub fn remote_target(
        &self,
        grant_id: &RemoteGrantId,
        authority_revision: Revision,
        verb: RemoteVerb,
        target: &RemoteTarget,
        now: i64,
    ) -> StoreResult<TargetFacts> {
        ready(&self.info)?;
        let grant = read::grant(&self.db, grant_id)?.ok_or_else(denied)?;
        if grant.store != self.info.id
            || grant.state != GrantState::Active
            || grant.expires_at_us <= now
            || grant.authority_revision != authority_revision
            || !matches!(verb, RemoteVerb::List | RemoteVerb::Watch)
            || !grant.scope.allows(verb, target)
        {
            return Err(denied());
        }
        let p = crate::identity::key(&self.db, "project", target.project.as_str(), &[0], false)?;
        let mut namespace = vec![1];
        namespace.extend_from_slice(&p);
        let a = crate::identity::key(&self.db, "agent", target.agent.as_str(), &namespace, false)?;
        let project_name: Option<String>=self.db.query_row("SELECT COALESCE(json_extract(v.facts,'$.name'),json_extract(f.facts,'$.name')) FROM projects p JOIN aux_data v ON v.event_seq=p.last_seq JOIN aux_data f ON f.event_seq=p.first_seq WHERE p.project_id=? AND p.state='active'",[&p],|r|r.get(0)).optional().map_err(sql)?;
        let project_name = project_name.ok_or_else(denied)?;
        let row=self.db.query_row("SELECT revision,last_seq,first_seq FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'",rusqlite::params![p,a],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql)?;
        let Read::Present { value: principal } = head(&self.db, &self.info, row)? else {
            return Err(denied());
        };
        let row = self
            .db
            .query_row(
                "SELECT revision,last_seq,last_seq FROM profiles WHERE project_id=? AND agent_id=?",
                rusqlite::params![p, a],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(sql)?;
        let profile = head(&self.db, &self.info, row)?;
        let row=self.db.query_row("SELECT revision,last_seq,first_seq FROM sessions WHERE project_id=? AND agent_id=? ORDER BY first_seq DESC LIMIT 1",rusqlite::params![p,a],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql)?;
        let session = head(&self.db, &self.info, row)?;
        // An activated session names its exact lifecycle. A newer registration for
        // the same agent must never substitute a different process as its witness.
        let activated = match &session {
            Read::Present { value } => match &value.current.body {
                EventBody::SessionActivated {
                    process: Some(process),
                    ..
                } => Some(process),
                _ => None,
            },
            _ => None,
        };
        let process_key = activated
            .map(|id| crate::identity::key(&self.db, "lifecycle", id.as_str(), &namespace, false))
            .transpose()?;
        let row=self.db.query_row("SELECT h.revision,h.last_seq,h.first_seq FROM processes h JOIN process_data d ON d.event_seq=h.last_seq WHERE h.project_id=?1 AND d.principal_id=?2 AND (?3 IS NULL OR h.process_id=?3) ORDER BY h.first_seq DESC LIMIT 1",rusqlite::params![p,a,process_key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql)?;
        let process = head(&self.db, &self.info, row)?;
        let pending: i64 = self
            .db
            .query_row(
                "SELECT unread_count FROM resume_heads WHERE project_id=? AND principal_id=?",
                rusqlite::params![p, a],
                |r| r.get(0),
            )
            .map_err(sql)?;
        Ok(TargetFacts {
            target: target.clone(),
            project_name,
            principal,
            profile,
            session,
            process,
            pending: u64::try_from(pending).map_err(invalid)?,
        })
    }
    pub fn remote_store_binding(&self, store: &StoreInfo, generation: u64) -> StoreResult<()> {
        ready(&self.info)?;
        if self.info.id != store.id || self.info.incarnation != store.incarnation {
            return Err(denied());
        }
        match self.runtime_owner()? {
            Read::Present { value } if value.generation.get() == generation => Ok(()),
            _ => Err(denied()),
        }
    }
}

impl ReadPhase {
    /// Keyset discovery under current machine authority. The result is bounded
    /// by page traffic, not by the number of registered agents or projects.
    pub fn remote_list_targets(
        &self,
        grant_id: &RemoteGrantId,
        revision: Revision,
        after: Option<&RemoteTarget>,
        limit: u16,
        now: i64,
    ) -> StoreResult<Vec<RemoteTarget>> {
        let grant = read::grant(&self.db, grant_id)?.ok_or_else(denied)?;
        if grant.store != self.info.id
            || grant.state != GrantState::Active
            || grant.authority_revision != revision
            || grant.expires_at_us <= now
            || !grant.scope.verbs.contains(&RemoteVerb::List)
            || !(1..=101).contains(&limit)
        {
            return Err(denied());
        }
        if !grant.scope.targets.is_empty() {
            let mut targets = grant.scope.targets;
            targets.sort();
            return Ok(targets
                .into_iter()
                .filter(|t| after.is_none_or(|a| t > a))
                .take(usize::from(limit))
                .collect());
        }
        let (p, a) = match after {
            Some(target) => {
                let p = crate::identity::key(
                    &self.db,
                    "project",
                    target.project.as_str(),
                    &[0],
                    false,
                )?;
                let mut namespace = vec![1];
                namespace.extend_from_slice(&p);
                let a = crate::identity::key(
                    &self.db,
                    "agent",
                    target.agent.as_str(),
                    &namespace,
                    false,
                )?;
                (Some(p), Some(a))
            }
            None => (None, None),
        };
        let mut query = self.db.prepare("SELECT a.project_id,a.principal_id FROM principals a JOIN projects p USING(project_id) WHERE a.principal_kind='agent' AND p.state='active' AND (?1 IS NULL OR a.project_id>?1 OR (a.project_id=?1 AND a.principal_id>?2)) ORDER BY a.project_id,a.principal_id LIMIT ?3").map_err(sql)?;
        let rows = query
            .query_map(rusqlite::params![p, a, i64::from(limit)], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        rows.into_iter()
            .map(|(p, a)| {
                let project = crate::identity::wire(&self.db, "project", &p, &[0])?
                    .try_into()
                    .map_err(invalid)?;
                let mut namespace = vec![1];
                namespace.extend_from_slice(&p);
                let agent = crate::identity::wire(&self.db, "agent", &a, &namespace)?
                    .try_into()
                    .map_err(invalid)?;
                Ok(RemoteTarget { project, agent })
            })
            .collect()
    }
}
