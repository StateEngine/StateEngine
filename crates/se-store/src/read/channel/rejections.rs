//! Recent input failures use a bounded reverse index seek, never a floor count.
use super::*;
impl SqliteSnapshot {
    pub(crate) fn read_recent_rejections(&self, id: &ChannelId) -> StoreResult<RecentRejections> {
        self.require_channel(id)?;
        type Row = (
            crate::channel::ExternalId,
            String,
            i64,
            String,
            Option<crate::channel::ExternalId>,
            i64,
            Option<String>,
        );
        let mut rows:Vec<Row>=self.db.prepare_cached("SELECT u.update_id,u.disposition,e.recorded_at_us,o.state,o.provider_message,s.recorded_at_us,o.failure FROM channel_outbox o JOIN channel_connections cc ON cc.id=o.connection_id JOIN channel_updates u ON u.connection_id=cc.id AND u.update_id=o.provider_update JOIN events e ON e.seq=u.handled_seq JOIN events s ON s.seq=o.last_seq WHERE o.connection_id=? AND o.kind='rejected' ORDER BY o.queued_seq DESC LIMIT 101").map_err(|e|self.read_sql(e))?.query_map([id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(|e|self.read_sql(e))?.collect::<Result<_,_>>().map_err(|e|self.read_sql(e))?;
        let more = rows.len() > 100;
        rows.truncate(100);
        let items = rows
            .into_iter()
            .map(
                |(update, json, at_us, output_state, provider_message, output_at_us, failure)| {
                    let Disposition::RejectedPaired { reason, .. } =
                        serde_json::from_str(&json).map_err(invalid)?
                    else {
                        return Err(invalid(
                            "private rejection output has no verified paired input",
                        ));
                    };
                    Ok(RejectedInput {
                        update,
                        reason,
                        at_us,
                        output_state,
                        provider_message,
                        output_at_us,
                        failure: failure
                            .map(|s| serde_json::from_str(&s).map_err(invalid))
                            .transpose()?,
                    })
                },
            )
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(RecentRejections { items, more })
    }
}
