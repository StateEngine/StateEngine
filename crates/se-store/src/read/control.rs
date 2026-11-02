//! Launch/stop target metadata for self, owner or creator control. Only the
//! target's principal, profile, live sessions and unreleased processes; never
//! its continuity, mail, turns or other private history.
use super::*;
/// More live sessions or processes than this refuses instead of truncating.
const LIVE_LIMIT: usize = 16;
impl SqliteSnapshot {
    pub(super) fn read_control_target(&self, target: AgentId) -> StoreResult<Read<ControlTarget>> {
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let a = key(&self.db, "agent", target.as_str(), &scope, false)?;
        let load = |seq| self.control_event(seq, &target);
        let principal = match self.head_with(
            "principals",
            "project_id=? AND principal_id=? AND principal_kind='agent'",
            &[&p, &a],
            Some("first_seq"),
            &load,
        )? {
            Read::Present { value } => value,
            _ => return Ok(self.absent("control target agent")),
        };
        match &self.scope.visibility {
            Visibility::Owner => {}
            Visibility::SelfOnly(actor) | Visibility::SharedProject(actor) if *actor == target => {}
            Visibility::SelfOnly(creator) | Visibility::SharedProject(creator) => {
                crate::creator::require(&self.db, &p, &scope, creator, &a)?
            }
        }
        let profile = self.head_with(
            "profiles",
            "project_id=? AND agent_id=?",
            &[&p, &a],
            None,
            &load,
        )?;
        let sessions = self.control_heads(
            "SELECT revision,last_seq,first_seq FROM sessions WHERE project_id=? AND agent_id=? AND state IN ('prepared','active') ORDER BY first_seq LIMIT ?",
            &p,
            &a,
            "live sessions",
            &load,
        )?;
        let processes = self.control_heads(
            "SELECT h.revision,h.last_seq,h.first_seq FROM processes h JOIN process_data d ON d.event_seq=h.last_seq WHERE h.project_id=? AND d.principal_id=? AND h.ownership_released=0 AND h.state NOT IN ('exited','historical') ORDER BY h.first_seq LIMIT ?",
            &p,
            &a,
            "unreleased processes",
            &load,
        )?;
        Ok(Read::Present {
            value: ControlTarget {
                principal,
                profile,
                sessions,
                processes,
            },
        })
    }
    fn control_heads(
        &self,
        sql: &str,
        p: &[u8],
        a: &[u8],
        what: &str,
        load: &dyn Fn(i64) -> StoreResult<StoredEvent>,
    ) -> StoreResult<Vec<ProjectionRecord>> {
        let mut statement = self.db.prepare(sql).map_err(|e| self.read_sql(e))?;
        let rows = statement
            .query_map(rusqlite::params![p, a, LIVE_LIMIT as i64 + 1], |r| {
                Ok((
                    crate::sql_value::value::<u64>(r, 0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| self.read_sql(e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| self.read_sql(e))?;
        if rows.len() > LIVE_LIMIT {
            return Err(fail(
                StoreErrorCode::ReadIncomplete,
                format!("control target has more than {LIVE_LIMIT} {what}; use owner inventory"),
            ));
        }
        rows.into_iter()
            .map(|(revision, seq, first)| {
                Ok(ProjectionRecord {
                    revision: codec::revision(revision)?,
                    current: load(seq)?,
                    original: (first != seq)
                        .then(|| load(first).map(Box::new))
                        .transpose()?,
                })
            })
            .collect()
    }
    /// Only the target's own metadata, session and process facts load here;
    /// every other kind, including runtime ownership facts, refuses.
    fn control_event(&self, seq: i64, target: &AgentId) -> StoreResult<StoredEvent> {
        let e = load_event(&self.db, seq, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        let who = Actor::Agent(target.clone());
        let about_target = e.header.scope == self.scope.admission.scope
            && match &e.body {
                EventBody::PrincipalRegistered { principal, .. }
                | EventBody::PrincipalRenamed { principal, .. } => *principal == who,
                EventBody::ProfileSaved { agent, .. }
                | EventBody::SessionPrepared { agent, .. } => agent == target,
                EventBody::SessionActivated { session, .. }
                | EventBody::SessionEnded { session, .. }
                | EventBody::SessionRevoked { session, .. } => self.session_of(session, target)?,
                EventBody::ProcessRegistered { identity, .. }
                | EventBody::ProcessTransition { identity, .. } => identity.principal == who,
                _ => false,
            };
        if !about_target {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "control target read reached a fact outside the target's metadata",
            ));
        }
        Ok(e)
    }
    fn session_of(&self, session: &SessionId, target: &AgentId) -> StoreResult<bool> {
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let id = key(&self.db, "session", session.as_str(), &scope, false)?;
        let a = key(&self.db, "agent", target.as_str(), &scope, false)?;
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND session_id=? AND agent_id=?)",
                rusqlite::params![p, id, a],
                |r| r.get(0),
            )
            .map_err(|error| self.read_sql(error))
    }
}
