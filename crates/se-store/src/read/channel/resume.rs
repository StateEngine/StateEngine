//! Exact, Owner-only action lookup and indexed confirmed-action recovery.
use super::*;
impl SqliteSnapshot {
    pub(crate) fn read_channel_action(
        &self,
        id: &ChannelId,
        action: &ActionId,
    ) -> StoreResult<Read<ResumeAction>> {
        self.require_channel(id)?;
        let json: Option<String> = self
            .db
            .query_row(
                "SELECT action_json FROM channel_actions WHERE connection_id=? AND id=?",
                crate::sql_value::sql_params![id.as_str(), action.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| self.read_sql(e))?;
        json.map(|json| {
            serde_json::from_str(&json)
                .map(|value| Read::Present { value })
                .map_err(invalid)
        })
        .unwrap_or_else(|| Ok(self.absent("phone lifecycle action")))
    }
    pub(crate) fn read_message_action(
        &self,
        id: &ChannelId,
        message: &se_types::MessageId,
    ) -> StoreResult<Read<ResumeAction>> {
        let state = self.require_channel(id)?;
        let scope = scope_key(&self.db, &Scope::Project(state.target.project), false)?;
        let message = key(&self.db, "message", message.as_str(), &scope, false)?;
        let json: Option<String> = self
            .db
            .query_row(
                "SELECT action_json FROM channel_actions WHERE connection_id=? AND original_id=?",
                crate::sql_value::sql_params![id.as_str(), message],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| self.read_sql(e))?;
        json.map(|json| {
            serde_json::from_str(&json)
                .map(|value| Read::Present { value })
                .map_err(invalid)
        })
        .unwrap_or_else(|| Ok(self.absent("phone lifecycle action")))
    }
    pub(crate) fn read_confirmed_actions(&self, id: &ChannelId) -> StoreResult<Vec<ResumeAction>> {
        self.require_channel(id)?;
        let json:Vec<String>=self.db.prepare_cached("SELECT action_json FROM channel_actions WHERE connection_id=? AND state='confirmed' ORDER BY last_seq LIMIT 10").map_err(|e|self.read_sql(e))?.query_map([id.as_str()],|r|r.get(0)).map_err(|e|self.read_sql(e))?.collect::<Result<_,_>>().map_err(|e|self.read_sql(e))?;
        json.into_iter()
            .map(|json| serde_json::from_str(&json).map_err(invalid))
            .collect()
    }
}
