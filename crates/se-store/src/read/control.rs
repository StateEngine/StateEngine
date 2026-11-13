//! Launch/stop target metadata for self, owner or creator control. Only the
//! target's principal, profile, live sessions and unreleased processes; never
//! its continuity, mail, turns or other private history.
use super::*;
/// More live sessions or processes than this refuses instead of truncating.
const LIVE_LIMIT: usize = 16;
/// More recorded moves than this refuses instead of truncating.
const MOVED_LIMIT: usize = 64;
impl SqliteSnapshot {
    pub(super) fn read_control_target(&self, target: AgentId) -> StoreResult<Read<ControlTarget>> {
        if self.remote_launch_grant.is_some() {
            self.require_remote_target(&target)?;
        }
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let a = key(&self.db, "agent", target.as_str(), &scope, false)?;
        let moved_from = self.moved_from_roots(&p)?;
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
            Visibility::None if self.remote_launch_grant.is_some() => (),
            Visibility::None => {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "no local control authority",
                ));
            }
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
            "SELECT h.revision,h.last_seq,h.first_seq FROM processes h INDEXED BY processes_live JOIN process_data d ON d.event_seq=h.last_seq WHERE h.project_id=? AND d.principal_id=? AND h.ownership_released=0 AND h.state NOT IN ('exited','historical') ORDER BY h.first_seq LIMIT ?",
            &p,
            &a,
            "unreleased processes",
            &load,
        )?;
        // The newest session and process in any state, so stop/status/resume
        // can tell a witnessed exit from a human-released StopUnproved.
        let latest_session = self.head_with(
            "sessions",
            "project_id=? AND agent_id=? AND first_seq=(SELECT MAX(first_seq) FROM sessions WHERE project_id=? AND agent_id=?)",
            &[&p, &a, &p, &a],
            Some("first_seq"),
            &load,
        )?;
        // The newest session a launch may auto-resume: the same selector as
        // latest_session except a revoked preparation that never activated
        // never shadows an older resumable session.
        let resume_session = self.head_with(
            "sessions",
            "project_id=? AND agent_id=? AND first_seq=(SELECT MAX(s2.first_seq) FROM sessions s2 WHERE s2.project_id=? AND s2.agent_id=? AND (s2.state != 'revoked' OR EXISTS (SELECT 1 FROM events e WHERE e.session_id = s2.session_id AND e.kind = 'session.activated')))",
            &[&p, &a, &p, &a],
            Some("first_seq"),
            &load,
        )?;
        let latest_process = self.head_with(
            "processes INDEXED BY processes_order",
            "project_id=? AND first_seq=(SELECT MAX(d.event_seq) FROM process_data d CROSS JOIN processes h ON h.first_seq=d.event_seq AND h.project_id=? WHERE d.principal_id=?)",
            &[&p, &p, &a],
            Some("first_seq"),
            &load,
        )?;
        Ok(Read::Present {
            value: ControlTarget {
                principal,
                profile,
                sessions,
                processes,
                latest_session,
                resume_session,
                latest_process,
                moved_from_roots: moved_from,
            },
        })
    }
    /// Every registered root this project moved away from, newest move
    /// first. A resumed provider transcript stays under the slug of the
    /// root where it was written, so the launch plan probes these roots
    /// before the current location; more than the bound refuses instead of
    /// truncating.
    fn moved_from_roots(&self, p: &[u8]) -> StoreResult<Vec<se_types::NativePath>> {
        let mut statement = self
            .db
            .prepare("SELECT seq FROM events WHERE project_id=? AND kind='project.moved' ORDER BY seq DESC LIMIT ?")
            .map_err(|e| self.read_sql(e))?;
        let seqs = statement
            .query_map(rusqlite::params![p, (MOVED_LIMIT + 1) as i64], |r| r.get(0))
            .map_err(|e| self.read_sql(e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| self.read_sql(e))?;
        if seqs.len() > MOVED_LIMIT {
            return Err(fail(
                StoreErrorCode::ReadIncomplete,
                format!(
                    "control target project has more than {MOVED_LIMIT} moves; use owner inventory"
                ),
            ));
        }
        let mut roots = Vec::new();
        for seq in seqs {
            let event = load_event(&self.db, seq, &self.info)
                .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
            if event.header.scope != self.scope.admission.scope {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "move history reached a fact outside the admitted project",
                ));
            }
            let EventBody::ProjectMoved { from, .. } = &event.body else {
                return Err(fail(
                    StoreErrorCode::Corrupt,
                    "move history row decodes to a different event kind",
                ));
            };
            for root in from {
                if !roots.iter().any(|seen| seen == &root.path) {
                    roots.push(root.path.clone());
                }
            }
        }
        Ok(roots)
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
        let about_target = e.header.scope == self.scope.admission.scope
            && match &e.body {
                EventBody::PrincipalRenamed { principal, .. } => {
                    *principal == Actor::Agent(target.clone())
                }
                EventBody::ProfileSaved { agent, .. } => agent == target,
                body => self.agent_fact(body, target)?.unwrap_or(false),
            };
        if !about_target {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "control target read reached a fact outside the target's metadata",
            ));
        }
        Ok(e)
    }
    pub(super) fn session_of(&self, session: &SessionId, target: &AgentId) -> StoreResult<bool> {
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
