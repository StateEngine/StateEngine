use super::*;
use crate::atlas_resume::AtlasResumeHead;
use se_types::{AtlasRootId, IndexEpochId, code::AtlasCursor};
impl SqliteSnapshot {
    /// Private point read for the verified viewer; never included in public history.
    pub fn atlas_resume_cursor(
        &self,
        viewer: &AgentId,
        root: &AtlasRootId,
        epoch: &IndexEpochId,
    ) -> StoreResult<Read<AtlasResumeHead>> {
        if !matches!(&self.scope.visibility, Visibility::Owner)
            && self.scope.admission.actor != Actor::Agent(viewer.clone())
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "another agent's Atlas resume cursor is private",
            ));
        }
        if self.info.schema_version < 5 {
            return Ok(Read::Unknown {
                what: "Private Atlas delivery state awaits the next owner migration".into(),
            });
        }
        let project = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let agent = key(&self.db, "agent", viewer.as_str(), &scope, false)?;
        let current: Option<String> = self
            .db
            .query_row(
                "SELECT epoch FROM atlas_resume_roots WHERE project_id=?1 AND root=?2 AND active=1",
                rusqlite::params![project, root.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| self.read_sql(e))?;
        if current.as_deref() != Some(epoch.as_str()) {
            return Ok(Read::Unknown {
                what: "Atlas root epoch is not active in the private delivery store".into(),
            });
        }
        let value:Option<(String,u64,u64)>=self.db.query_row("SELECT cursor,revision,fence FROM atlas_resume_cursors WHERE project_id=?1 AND root=?2 AND agent_id=?3",rusqlite::params![project,root.as_str(),agent],|r|Ok((r.get(0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?))).optional().map_err(|e|self.read_sql(e))?;
        Ok(Read::Present {
            value: match value {
                Some((cursor, revision, fence)) => AtlasResumeHead {
                    cursor: Some(AtlasCursor::new(cursor).map_err(invalid)?),
                    revision,
                    fence,
                },
                None => AtlasResumeHead {
                    cursor: None,
                    revision: 0,
                    fence: 0,
                },
            },
        })
    }
}
