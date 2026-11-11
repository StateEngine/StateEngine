//! Indexed outbox seeks for delivery and receipt readback, never a floor scan.
use super::*;
impl SqliteSnapshot {
    pub(crate) fn read_channel_capacity(&self, id: &ChannelId) -> StoreResult<bool> {
        self.require_channel(id)?;
        crate::apply::channel_capacity(&self.db, id)
    }

    pub(crate) fn read_channel_due_delays(
        &self,
        id: &ChannelId,
        at_us: i64,
    ) -> StoreResult<Vec<se_types::MessageId>> {
        let state = self.require_channel(id)?;
        let scope = scope_key(&self.db, &Scope::Project(state.target.project), false)?;
        let rows:Vec<Vec<u8>>=self.db.prepare_cached("SELECT message_id FROM channel_updates WHERE connection_id=? AND status_due_at_us<=? ORDER BY status_due_at_us,handled_seq LIMIT 10").map_err(|e|self.read_sql(e))?.query_map(crate::sql_value::sql_params![id.as_str(),at_us],|r|r.get(0)).map_err(|e|self.read_sql(e))?.collect::<Result<_,_>>().map_err(|e|self.read_sql(e))?;
        rows.into_iter()
            .map(|bytes| {
                wire(&self.db, "message", &bytes, &scope)?
                    .try_into()
                    .map_err(invalid)
            })
            .collect()
    }

    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(crate) fn read_outputs(
        &self,
        id: &ChannelId,
        after: u64,
        original: Option<&se_types::MessageId>,
        pending_at: Option<i64>,
    ) -> StoreResult<ChannelRows<Outbound>> {
        let state = self.require_channel(id)?;
        let scope = scope_key(&self.db, &Scope::Project(state.target.project), false)?;
        let original = original
            .map(|m| key(&self.db, "message", m.as_str(), &scope, false))
            .transpose()?;
        let ready = if pending_at.is_some() {
            "AND state IN ('queued','sending') AND (retry_at_us IS NULL OR retry_at_us<=?4)"
        } else {
            "AND ?4 IS NULL"
        };
        let reply = if original.is_some() {
            "AND original_id=?3 AND kind='reply'"
        } else {
            "AND ?3 IS NULL"
        };
        let predicate = format!("connection_id=?1 AND queued_seq>?2 {reply} {ready}");
        let parameters = [
            crate::sql_value::param(&id.as_str())?,
            crate::sql_value::param(&after)?,
            crate::sql_value::param(&original)?,
            crate::sql_value::param(&pending_at)?,
        ];
        let total: u64 = self
            .db
            .query_row(
                &format!("SELECT count(*) FROM channel_outbox WHERE {predicate}"),
                rusqlite::params_from_iter(parameters.iter()),
                |r| crate::sql_value::value(r, 0),
            )
            .map_err(|e| self.read_sql(e))?;
        type Row = (
            u64,
            u64,
            u64,
            String,
            String,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            String,
            Option<crate::channel::ExternalId>,
            Option<i64>,
            i64,
            Option<crate::channel::ExternalId>,
            Option<String>,
            String,
        );
        let limit = if pending_at.is_some() { 10 } else { 100 };
        let rows:Vec<Row>=self.db.prepare_cached(&format!("SELECT queued_seq,binding_revision,attempt,output_id,kind,original_id,reply_id,state,provider_message,retry_at_us,(SELECT recorded_at_us FROM events WHERE seq=channel_outbox.last_seq),provider_update,failure,provider_messages FROM channel_outbox WHERE {predicate} ORDER BY queued_seq LIMIT {limit}")).map_err(|e|self.read_sql(e))?.query_map(rusqlite::params_from_iter(parameters.iter()),|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?))).map_err(|e|self.read_sql(e))?.collect::<Result<_,_>>().map_err(|e|self.read_sql(e))?;
        let end = rows.last().map(|r| r.0).unwrap_or(after);
        let mut items = Vec::new();
        for (
            _,
            binding_revision,
            attempt,
            output,
            kind,
            original,
            reply,
            state,
            provider_message,
            retry_at_us,
            at_us,
            provider_update,
            failure,
            provider_messages,
        ) in rows
        {
            let decode = |bytes: Vec<u8>| {
                wire(&self.db, "message", &bytes, &scope)?
                    .try_into()
                    .map_err(invalid)
            };
            let rejection = if let Some(update) = &provider_update {
                let json:String=self.db.query_row("SELECT disposition FROM channel_updates WHERE connection_id=? AND update_id=?",crate::sql_value::sql_params![id.as_str(),update],|r|r.get(0)).map_err(|e|self.read_sql(e))?;
                let Disposition::RejectedPaired { reason, .. } =
                    serde_json::from_str(&json).map_err(invalid)?
                else {
                    return Err(invalid("private rejection output has no paired input"));
                };
                Some(reason)
            } else {
                None
            };
            items.push(Outbound {
                connection: id.clone(),
                binding_revision,
                attempt,
                at_us,
                output: OutputId::new(output).map_err(invalid)?,
                kind,
                original: original.map(decode).transpose()?,
                reply: reply.map(decode).transpose()?,
                state,
                provider_message,
                provider_messages: serde_json::from_str(&provider_messages).map_err(invalid)?,
                retry_at_us,
                rejection,
                provider_update,
                failure: failure
                    .map(|s| serde_json::from_str(&s).map_err(invalid))
                    .transpose()?,
            });
        }
        Ok(ChannelRows {
            omitted: total.saturating_sub(items.len() as u64),
            items,
            after: end,
        })
    }
}
