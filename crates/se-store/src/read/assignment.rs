//! Assignment visibility follows its assignee and current project captain.
use super::*;

impl SqliteSnapshot {
    pub(super) fn is_assignment_captain(&self, agent: &AgentId) -> StoreResult<bool> {
        if let Some(captain) = self.assignment_captain.get() {
            return Ok(captain.as_ref() == Some(&Actor::Agent(agent.clone())));
        }
        let project = self.project_bytes()?;
        let seq: Option<i64> = self
            .db
            .query_row(
                "SELECT last_seq FROM project_captain WHERE project_id=?",
                [project],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        let captain: Option<Actor> = match seq {
            Some(seq) => codec::field(&codec::facts(&self.db, seq)?, "captain")?,
            None => None,
        };
        let matches = captain.as_ref() == Some(&Actor::Agent(agent.clone()));
        let _ = self.assignment_captain.set(captain);
        Ok(matches)
    }

    fn captain_may_inspect(
        &self,
        agent: &AgentId,
        state: &str,
        last_seq: i64,
    ) -> StoreResult<bool> {
        if matches!(state, "open" | "working" | "blocked") {
            return self.is_assignment_captain(agent);
        }
        let recorded: Actor = codec::field(&codec::facts(&self.db, last_seq)?, "captain")?;
        Ok(recorded == Actor::Agent(agent.clone()))
    }

    pub(super) fn assignment_visible(&self, id: &EventId, agent: &AgentId) -> StoreResult<bool> {
        let project = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let id = key(&self.db, "event", id.as_str(), &scope, false)?;
        let agent_key = key(&self.db, "agent", agent.as_str(), &scope, false)?;
        let row: Option<(Vec<u8>, String, i64)> = self
            .db
            .query_row(
                "SELECT assignee_id,state,last_seq FROM assignments WHERE project_id=? AND assignment_id=?",
                crate::sql_value::sql_params![project, id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        let Some((assignee, state, last_seq)) = row else {
            return Ok(false);
        };
        Ok(assignee == agent_key || self.captain_may_inspect(agent, &state, last_seq)?)
    }

    fn has_assignment_floor(&self) -> StoreResult<bool> {
        if let Some(value) = self.assignment_floor_exists.get() {
            return Ok(*value);
        }
        let project = self.project_bytes()?;
        let value: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM assignment_floor_events WHERE project_id=?)",
                [project],
                |row| row.get(0),
            )
            .map_err(|error| self.read_sql(error))?;
        let _ = self.assignment_floor_exists.set(value);
        Ok(value)
    }

    pub(super) fn assignment_floor_visible(
        &self,
        event: &EventId,
        agent: &AgentId,
    ) -> StoreResult<bool> {
        if self.info.schema_version < 16 || !self.has_assignment_floor()? {
            return Ok(false);
        }
        let project = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let event = key(&self.db, "event", event.as_str(), &scope, false)?;
        let row: Option<(String, i64)> = self.db.query_row(
            "SELECT a.state,a.last_seq FROM assignment_floor_events f JOIN assignments a ON a.project_id=f.project_id AND a.assignment_id=f.assignment_id WHERE f.project_id=? AND f.floor_event_id=?",
            crate::sql_value::sql_params![project,event], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error| self.read_sql(error))?;
        match row {
            Some((state, last_seq)) => self.captain_may_inspect(agent, &state, last_seq),
            None => Ok(false),
        }
    }
}
