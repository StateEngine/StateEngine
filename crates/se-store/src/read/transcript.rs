//! Finite, authority-scoped provider metadata reads; no provider payload is searched.
use super::*;
impl SqliteSnapshot {
    pub(super) fn read_transcript_events(
        &self,
        agent: AgentId,
        session: Option<SessionId>,
        budget: ReadBudget,
    ) -> StoreResult<TranscriptRecords> {
        let until = query::deadline(&budget)?;
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        let (head, _) = self.window(&budget, &format!("transcript-events:{agent}"), false)?;
        let mut filter = String::from(
            "t.project_id=? AND t.agent_id=? AND t.event_seq<=? AND t.role='system' AND t.vendor_ref LIKE 'se.notice.v1/%'",
        );
        let mut params = vec![
            rusqlite::types::Value::Blob(p),
            rusqlite::types::Value::Blob(a),
            rusqlite::types::Value::Integer(head as i64),
        ];
        if let Some(session) = session {
            let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
            let id = key(&self.db, "session", session.as_str(), &scope, false)?;
            filter.push_str(" AND t.session_id=?");
            params.push(rusqlite::types::Value::Blob(id));
        }
        let mut limited = params.clone();
        limited.push(rusqlite::types::Value::Integer(i64::from(
            budget.page.limit.get(),
        )));
        let select = format!(
            "SELECT 1,t.event_seq,t.event_seq FROM turn_data t INDEXED BY turn_data_agent_seq WHERE {filter} ORDER BY t.event_seq DESC LIMIT ?"
        );
        let rows = self.query_seqs_before(&select, limited, until)?;
        let mut bytes = 0;
        let mut events = Vec::new();
        for (_, seq, _) in rows {
            query::check_deadline(until)?;
            let event = self.record(seq)?;
            bytes += query::event_size(&event)?;
            if bytes > u64::from(budget.page.max_bytes.get()) {
                return Err(fail(
                    StoreErrorCode::ReadBudgetTooSmall,
                    "transcript metadata exceeds its byte bound",
                ));
            }
            events.push(event);
        }
        let left = |name: &str| -> StoreResult<ReadBudget> {
            let mut b = budget.clone();
            b.deadline = until
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    fail(
                        StoreErrorCode::ReadIncomplete,
                        format!("{name} exceeded the original metadata read deadline"),
                    )
                })?;
            Ok(b)
        };
        let count = self.query_seqs(
            &format!(
                "SELECT 1,count(*),1 FROM turn_data t INDEXED BY turn_data_agent_seq WHERE {filter}"
            ),
            params.clone(),
            &left("metadata count")?,
        )?;
        let count = count.first().map_or(0, |r| r.1 as u64);
        let latest=self.query_seqs(&format!("SELECT 1,t.event_seq,t.event_seq FROM turn_data t INDEXED BY turn_data_agent_seq WHERE {filter} AND t.vendor_ref LIKE 'se.notice.v1/compact/%' ORDER BY t.event_seq DESC LIMIT 1"),params,&left("latest compaction")?)?;
        let last_compaction = match latest.first() {
            Some((_, seq, _)) => Read::Present {
                value: self.record(*seq)?,
            },
            None => self.absent("recorded provider compaction"),
        };
        query::check_deadline(until)?;
        Ok(TranscriptRecords {
            omitted: count.saturating_sub(events.len() as u64),
            events,
            last_compaction,
        })
    }
}
