//! Native conversation bindings select exact sessions before paging chat rows.
use super::*;
use rusqlite::types::Value;
use std::collections::BTreeSet;

impl SqliteSnapshot {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) fn read_conversation_turns(
        &self,
        agent: AgentId,
        provider: Provider,
        native_ref: &str,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        let deadline = query::deadline(&budget)?;
        let project = self.project_bytes()?;
        let agent_key = self.agent_bytes(&agent)?;
        let binding = format!(
            "history:conversation:{}:{provider:?}:{native_ref}",
            agent.as_str()
        );
        let (high, after) = self.window(&budget, &binding, false)?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let project_wire = crate::identity::project(&self.scope.admission.scope)?;
        let mut sessions = BTreeSet::new();
        let mut source_after = 0i64;
        loop {
            let rows = self.query_seqs_before(
                "SELECT 1,event_seq,event_seq FROM aux_data INDEXED BY capture_source_natural
                 WHERE json_extract(facts,'$.capture_kind')='source'
                 AND json_extract(facts,'$.project')=? AND json_extract(facts,'$.native_ref')=?
                 AND json_extract(facts,'$.consent')='Capture'
                 AND event_seq>? AND event_seq<=? ORDER BY event_seq LIMIT 128",
                vec![
                    Value::Text(project_wire.as_str().into()),
                    Value::Text(native_ref.into()),
                    Value::Integer(source_after),
                    Value::Integer(high as i64),
                ],
                deadline,
            )?;
            if rows.is_empty() {
                break;
            }
            for (_, seq, _) in rows {
                query::check_deadline(deadline)?;
                source_after = seq;
                // Select the indexed session before loading its private event.
                // A different agent may use the same native conversation name.
                let selected: String = self
                    .db
                    .query_row(
                        "SELECT json_extract(facts,'$.session') FROM aux_data WHERE event_seq=?",
                        [seq],
                        |row| row.get(0),
                    )
                    .map_err(|error| self.read_sql(error))?;
                let selected = SessionId::try_from(selected).map_err(invalid)?;
                if !self.session_visible(&selected, &agent)? {
                    continue;
                }
                let source = self.record(seq)?;
                let EventBody::CaptureSource {
                    session,
                    native_ref: found,
                    ..
                } = source.body
                else {
                    return Err(fail(
                        StoreErrorCode::ProjectionInconsistent,
                        "conversation binding is not a capture source",
                    ));
                };
                if found != native_ref || session != selected {
                    return Err(fail(
                        StoreErrorCode::ProjectionInconsistent,
                        "conversation source index differs from its record",
                    ));
                }
                sessions.insert(key(&self.db, "session", session.as_str(), &scope, false)?);
                if sessions.len() > 10000 {
                    return Err(fail(
                        StoreErrorCode::ReadIncomplete,
                        "captured conversation exceeds ten thousand source sessions",
                    ));
                }
            }
        }
        let placeholders = if sessions.is_empty() {
            "NULL".into()
        } else {
            vec!["?"; sessions.len()].join(",")
        };
        let sql = format!(
            "SELECT e.entity_revision,t.event_seq,t.event_seq
             FROM turn_data t INDEXED BY turn_data_session_seq JOIN events e ON e.seq=t.event_seq
             WHERE t.project_id=? AND t.agent_id=? AND t.provider=?
             AND t.role IN ('user','assistant') AND t.event_seq>? AND t.event_seq<=?
             AND t.session_id IN ({placeholders}) ORDER BY t.event_seq LIMIT ?"
        );
        let mut params = vec![
            Value::Blob(project),
            Value::Blob(agent_key),
            Value::Text(codec::capture::provider(provider).into()),
            Value::Integer(after as i64),
            Value::Integer(high as i64),
        ];
        params.extend(sessions.into_iter().map(Value::Blob));
        params.push(Value::Integer(i64::from(budget.page.limit.get()) + 1));
        let rows = self.query_seqs_before(&sql, params, deadline)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (_, seq, _) in rows {
            query::check_deadline(deadline)?;
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let event = self.record(seq)?;
            let cost = query::event_size(&event)?;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(query::budget_failure(
                        &budget,
                        cost,
                        "first complete conversation turn exceeds page bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            last = seq as u64;
            items.push(event);
        }
        query::check_deadline(deadline)?;
        self.page(
            items,
            &budget,
            &binding,
            page::PageFacts {
                h: high,
                after,
                last,
                bytes,
                stop,
                remaining: None,
            },
        )
    }
}
