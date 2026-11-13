//! Native process coordination gets approved control metadata, never Owner visibility.
use super::*;

impl ReadPhase {
    /// Not a remote read operation: only the native launch coordinator consumes
    /// this scoped pin. Ordinary snapshot construction still refuses devices.
    pub fn into_remote_launch_snapshot(self, admission: Admission) -> StoreResult<SqliteSnapshot> {
        let (Actor::Remote(principal), Scope::Project(project)) =
            (&admission.actor, &admission.scope)
        else {
            return Err(control_denied());
        };
        if self.info.schema_version < 12
            || self.info.state != StoreState::Ready
            || admission.session.is_some()
        {
            return Err(control_denied());
        }
        let principal =
            crate::identity::canonical(principal.as_str()).ok_or_else(control_denied)?;
        let mut q = self
            .db
            .prepare("SELECT grant_id FROM remote_grants WHERE principal_id=? LIMIT 2")
            .map_err(sql)?;
        let ids = q
            .query_map([principal], |r| r.get::<_, Vec<u8>>(0))
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        drop(q);
        if ids.len() != 1 {
            return Err(control_denied());
        }
        let grant = se_types::RemoteGrantId::from_bytes(
            ids[0].clone().try_into().map_err(|_| control_denied())?,
        )
        .map_err(|_| control_denied())?;
        let p = key(&self.db, "project", project.as_str(), &[0], false)?;
        let allowed:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM remote_launch_permissions WHERE grant_id=?1 AND allowed=1 AND json_extract(target,'$.project')=?2) OR EXISTS(SELECT 1 FROM remote_launch_attribution WHERE grant_id=?1 AND project_id=?3)",
            rusqlite::params![ids[0],project.as_str(),p],|r|r.get(0)).map_err(sql)?;
        if !allowed {
            return Err(control_denied());
        }
        Ok(SqliteSnapshot {
            db: self.db,
            remote_launch_grant: Some(grant),
            recycle: self.recycle,
            info: self.info,
            scope: ReadScope {
                admission,
                visibility: Visibility::None,
            },
            path: self.path,
            _slot: self.slot,
            _local: self.local,
        })
    }
}

impl SqliteSnapshot {
    pub(super) fn require_local_port(&self) -> StoreResult<()> {
        if self.remote_launch_grant.is_some() {
            return Err(control_denied());
        }
        Ok(())
    }
    pub(super) fn require_remote_target(&self, agent: &AgentId) -> StoreResult<()> {
        let Some(grant) = &self.remote_launch_grant else {
            return Err(control_denied());
        };
        let Scope::Project(project) = &self.scope.admission.scope else {
            return Err(control_denied());
        };
        let target = se_types::remote::RemoteTarget {
            project: project.clone(),
            agent: agent.clone(),
        };
        if !crate::remote::launch_target_owned(&self.db, grant, &target)? {
            return Err(control_denied());
        }
        Ok(())
    }
    pub(super) fn remote_launch_visible(&self, event: &StoredEvent) -> StoreResult<bool> {
        if event.header.scope != self.scope.admission.scope {
            return Ok(false);
        }
        let allowed = |agent: &AgentId| self.require_remote_target(agent).map(|()| true);
        Ok(match &event.body {
            EventBody::ProjectRegistered { .. }
            | EventBody::ProjectUpdated { .. }
            | EventBody::ProjectMoved { .. }
            | EventBody::ProjectRemoved { .. } => true,
            EventBody::PrincipalRegistered {
                principal: Actor::Agent(agent),
                ..
            }
            | EventBody::PrincipalRenamed {
                principal: Actor::Agent(agent),
                ..
            }
            | EventBody::ProfileSaved { agent, .. }
            | EventBody::SessionPrepared { agent, .. } => allowed(agent)?,
            EventBody::SessionActivated { session, .. }
            | EventBody::SessionEnded { session, .. }
            | EventBody::SessionRevoked { session, .. }
            | EventBody::CaptureSource { session, .. }
            | EventBody::CaptureVerified { session, .. }
            | EventBody::CaptureFailed { session, .. } => self.remote_session_visible(session)?,
            EventBody::CaptureProgress { source, .. } => self.remote_capture_visible(source)?,
            EventBody::ProcessRegistered { identity, .. }
            | EventBody::ProcessTransition { identity, .. } => match &identity.principal {
                Actor::Agent(agent) => allowed(agent)?,
                _ => false,
            },
            EventBody::RemoteLaunchAttributed { record } => {
                self.remote_launch_grant.as_ref() == Some(&record.attribution.grant)
            }
            _ => false,
        })
    }
    fn remote_capture_visible(&self, source: &RecordId) -> StoreResult<bool> {
        let p = self.project_bytes()?;
        let session: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT session_id FROM capture_sources WHERE project_id=? AND source_id=?",
                rusqlite::params![p, source.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        let Some(session) = session else {
            return Ok(false);
        };
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let session = crate::identity::wire(&self.db, "session", &session, &scope)?
            .try_into()
            .map_err(invalid)?;
        self.remote_session_visible(&session)
    }
    fn remote_session_visible(&self, session: &SessionId) -> StoreResult<bool> {
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let s = key(&self.db, "session", session.as_str(), &scope, false)?;
        let a: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT agent_id FROM sessions WHERE project_id=? AND session_id=?",
                rusqlite::params![p, s],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        let Some(a) = a else { return Ok(false) };
        let agent = crate::identity::wire(&self.db, "agent", &a, &scope)?
            .try_into()
            .map_err(invalid)?;
        self.require_remote_target(&agent)?;
        Ok(true)
    }
}
fn control_denied() -> Box<StoreError> {
    fail(
        StoreErrorCode::ScopeMismatch,
        "this closed native launch view carries only Owner-approved target control metadata; use the launched agent's own current session for mail, turns and working state",
    )
}
