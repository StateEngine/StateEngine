//! Recorded process inventory, durable effect intentions and owned
//! integrations. Reads never execute an effect or observe the OS.
use super::*;
fn blob(v: Vec<u8>) -> rusqlite::types::Value {
    rusqlite::types::Value::Blob(v)
}
impl SqliteSnapshot {
    pub(super) fn read_processes(&self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        let p = self.project_bytes()?;
        if let Visibility::SelfOnly(agent) = &self.scope.visibility {
            let a = self.agent_bytes(agent)?;
            return self.list_heads(
                "processes",
                "first_seq",
                "project_id=? AND EXISTS(SELECT 1 FROM process_data d WHERE d.event_seq=processes.last_seq AND d.principal_id=?)",
                vec![blob(p), blob(a)],
                budget,
            );
        }
        self.list_heads(
            "processes",
            "first_seq",
            "project_id=?",
            vec![blob(p)],
            budget,
        )
    }
    /// Pending and offered effects in request order; a self-scoped agent sees
    /// only effects naming it as the affected principal.
    pub(super) fn read_pending_effects(
        &self,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let mut filter = String::from("project_id=? AND state IN ('pending','offered')");
        let mut keys = vec![blob(p)];
        if let Visibility::SelfOnly(agent) = &self.scope.visibility {
            filter.push_str(" AND principal_id=?");
            keys.push(blob(self.agent_bytes(agent)?));
        }
        self.list_heads("effects", "requested_seq", &filter, keys, budget)
    }
    pub(super) fn read_effect(&self, id: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let id = id.as_bytes().to_vec();
        self.head(
            "effects",
            "project_id=? AND effect_id=?",
            &[&p, &id],
            Some("requested_seq"),
        )
    }
    /// Owned file edits are owner metadata; a self-scoped agent is refused
    /// rather than shown an empty list.
    pub(super) fn read_integrations(
        &self,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        if let Visibility::SelfOnly(_) = &self.scope.visibility {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "integration records are owner metadata",
            ));
        }
        let p = self.project_bytes()?;
        self.list_heads(
            "integrations",
            "last_seq",
            "project_id=?",
            vec![blob(p)],
            budget,
        )
    }
    /// The agent's current cursor for one purpose, as issued; an
    /// acknowledgment is a later head event in history, never a new window.
    pub(super) fn read_cursor(
        &self,
        agent: AgentId,
        purpose: String,
    ) -> StoreResult<Read<CursorRecord>> {
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        let issued: Option<i64> = self
            .db
            .query_row(
                "SELECT d.event_seq FROM cursors h JOIN cursor_data d ON d.cursor_id=h.cursor_id AND d.acknowledged_event IS NULL WHERE h.project_id=? AND h.agent_id=? AND h.purpose=?",
                rusqlite::params![p, a, purpose],
                |r| r.get(0),
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        let Some(seq) = issued else {
            return Ok(self.absent("cursor"));
        };
        match self.record(seq)?.body {
            EventBody::CursorRecorded { cursor } => Ok(Read::Present { value: *cursor }),
            _ => Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "cursor head does not name its issuing event",
            )),
        }
    }
    pub(super) fn cursor_visible(&self, cursor: &RecordId, agent: &AgentId) -> StoreResult<bool> {
        let p = self.project_bytes()?;
        let a = self.agent_bytes(agent)?;
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cursor_data d JOIN events e ON e.seq=d.event_seq WHERE e.project_id=? AND d.cursor_id=? AND d.agent_id=?)",
                rusqlite::params![p, cursor.as_bytes().as_slice(), a],
                |r| r.get(0),
            )
            .map_err(|error| self.read_sql(error))
    }
    pub(super) fn effect_visible(&self, effect: &RecordId, agent: &AgentId) -> StoreResult<bool> {
        let p = self.project_bytes()?;
        let a = self.agent_bytes(agent)?;
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM effects WHERE project_id=? AND effect_id=? AND principal_id=?)",
                rusqlite::params![p, effect.as_bytes().as_slice(), a],
                |r| r.get(0),
            )
            .map_err(|error| self.read_sql(error))
    }
}
