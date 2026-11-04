//! One authorized, fixed-high-water candidate stream for history and search.
use super::*;
use rusqlite::types::Value;

pub(super) struct HistoryStream {
    pub binding: String,
    pub high: u64,
    pub after: u64,
    pub sql: String,
    pub params: Vec<Value>,
    exact_session: Option<SessionId>,
}
impl SqliteSnapshot {
    pub(super) fn history_stream(
        &self,
        query: &HistoryQuery,
        budget: &ReadBudget,
        search: Option<&str>,
    ) -> StoreResult<HistoryStream> {
        let s = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let mut binding = format!(
            "history:{}:{:?}:{:?}:{:?}:{:?}:{:?}",
            codec::encode(&s)?,
            self.scope.admission.actor,
            query.agent,
            query.session,
            (&query.kinds, &query.families, query.transcript),
            query.since.as_ref().map(StorePosition::sequence)
        );
        if let Some(text) = search {
            binding.push_str(&format!(":search:{}", codec::encode(&text)?));
        }
        let (h, mut after) = self.window(budget, &binding, false)?;
        if let Some(position) = &query.since {
            if !position.belongs(&self.info) {
                return Err(fail(
                    StoreErrorCode::CursorStale,
                    "history position belongs to another store/incarnation",
                ));
            }
            after = after.max(position.sequence());
        }
        if after > h {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "history start is beyond snapshot",
            ));
        }
        let p = match &self.scope.admission.scope {
            Scope::Registry => None,
            _ => Some(self.project_bytes()?),
        };
        let exact_session = query.session.as_ref().filter(|_| {
            !query.kinds.is_empty() && query.kinds.iter().all(|k| *k == EventKind::SessionTurn)
        });
        let mut sql = if exact_session.is_some() {
            "SELECT e.entity_revision,e.seq,e.seq FROM turn_data t INDEXED BY turn_data_session_seq JOIN events e ON e.seq=t.event_seq WHERE t.project_id IS ? AND t.event_seq>? AND t.event_seq<=?".to_string()
        } else {
            "SELECT e.entity_revision,e.seq,e.seq FROM events e WHERE e.project_id IS ? AND e.seq>? AND e.seq<=?".to_string()
        };
        if exact_session.is_none() {
            sql.push_str(" AND e.kind NOT IN ('runtime.owner','runtime.handover')");
        }
        let mut params = vec![
            p.map(rusqlite::types::Value::Blob)
                .unwrap_or(rusqlite::types::Value::Null),
            rusqlite::types::Value::Integer(after as i64),
            rusqlite::types::Value::Integer(h as i64),
        ];
        if let Some(agent) = &query.agent {
            let a = self.agent_bytes(agent)?;
            sql.push_str(" AND (e.actor_id=?
                OR EXISTS(SELECT 1 FROM turn_data d WHERE d.event_seq=e.seq AND d.project_id=? AND d.agent_id=? AND d.event_seq>? AND d.event_seq<=?)
                OR EXISTS(SELECT 1 FROM process_data d WHERE d.event_seq=e.seq AND d.principal_id=?))");
            params.extend([
                rusqlite::types::Value::Blob(a.clone()),
                rusqlite::types::Value::Blob(self.project_bytes()?),
                rusqlite::types::Value::Blob(a.clone()),
                rusqlite::types::Value::Integer(after as i64),
                rusqlite::types::Value::Integer(h as i64),
                rusqlite::types::Value::Blob(a),
            ]);
        }
        if let Some(session) = &query.session {
            let k = key(&self.db, "session", session.as_str(), &s, false)?;
            sql.push_str(if exact_session.is_some() {
                " AND t.session_id=?"
            } else {
                " AND e.session_id=?"
            });
            params.push(rusqlite::types::Value::Blob(k));
        }
        if let Visibility::SelfOnly(agent) = &self.scope.visibility {
            let a = self.agent_bytes(agent)?;
            sql.push_str(" AND (e.actor_id=?
                OR EXISTS(SELECT 1 FROM messages d WHERE d.sent_seq=e.seq AND d.project_id=? AND d.recipient_id=? AND d.sent_seq>? AND d.sent_seq<=?)
                OR EXISTS(SELECT 1 FROM turn_data d WHERE d.event_seq=e.seq AND d.project_id=? AND d.agent_id=? AND d.event_seq>? AND d.event_seq<=?)
                OR EXISTS(SELECT 1 FROM process_data d WHERE d.event_seq=e.seq AND d.principal_id=?))");
            params.extend([
                rusqlite::types::Value::Blob(a.clone()),
                rusqlite::types::Value::Blob(self.project_bytes()?),
                rusqlite::types::Value::Blob(a.clone()),
                rusqlite::types::Value::Integer(after as i64),
                rusqlite::types::Value::Integer(h as i64),
                rusqlite::types::Value::Blob(self.project_bytes()?),
                rusqlite::types::Value::Blob(a.clone()),
                rusqlite::types::Value::Integer(after as i64),
                rusqlite::types::Value::Integer(h as i64),
                rusqlite::types::Value::Blob(a),
            ]);
        }
        match query.transcript {
            TranscriptFilter::All => {},
            TranscriptFilter::Chat => sql.push_str(" AND NOT EXISTS(SELECT 1 FROM turn_data t WHERE t.event_seq=e.seq AND t.role='system' AND t.vendor_ref LIKE 'se.notice.v1/%')"),
            TranscriptFilter::Metadata => sql.push_str(" AND (e.kind<>'session.turn' OR EXISTS(SELECT 1 FROM turn_data t WHERE t.event_seq=e.seq AND t.role='system' AND t.vendor_ref LIKE 'se.notice.v1/%'))"),
        }
        if !query.kinds.is_empty() && exact_session.is_none() {
            sql.push_str(" AND e.kind IN (");
            sql.push_str(&vec!["?"; query.kinds.len()].join(","));
            sql.push(')');
            for k in &query.kinds {
                params.push(rusqlite::types::Value::Text(query::kind_name(*k).into()));
            }
        }
        if exact_session.is_some() && !query.families.is_empty() {
            if !query.families.contains(&HistoryFamily::Turns) {
                sql.push_str(" AND 0");
            }
        } else if !query.families.is_empty() {
            let mut prefixes = Vec::new();
            for f in &query.families {
                prefixes.extend(family_prefixes(*f))
            }
            sql.push_str(" AND (");
            sql.push_str(&vec!["e.kind LIKE ?"; prefixes.len()].join(" OR "));
            sql.push(')');
            for prefix in prefixes {
                params.push(rusqlite::types::Value::Text(format!("{prefix}%")));
            }
        }

        sql.push_str(if exact_session.is_some() {
            " ORDER BY t.event_seq LIMIT ?"
        } else {
            " ORDER BY e.seq LIMIT ?"
        });
        Ok(HistoryStream {
            binding,
            high: h,
            after,
            sql,
            params,
            exact_session: exact_session.cloned(),
        })
    }
    pub(super) fn history_event(
        &self,
        seq: i64,
        stream: &HistoryStream,
    ) -> StoreResult<StoredEvent> {
        let event = self.record(seq)?;
        if let Some(session) = &stream.exact_session
            && !(matches!(&event.body, EventBody::SessionTurn { session: actual, .. } if actual == session)
                && event.header.session.as_ref() == Some(session)
                && event.header.scope == self.scope.admission.scope)
        {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "session-turn index differs from its immutable event",
            ));
        }
        Ok(event)
    }
    pub(super) fn read_history(
        &self,
        mut query: HistoryQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        let deadline = query::deadline(&budget)?;
        normalize(&mut query);
        let stream = self.history_stream(&query, &budget, None)?;
        let mut params = stream.params.clone();
        params.push(Value::Integer(i64::from(budget.page.limit.get()) + 1));
        let rows = self.query_seqs_before(&stream.sql, params, deadline)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = stream.after;
        let mut stop = StopReason::Exhausted;
        for (_, seq, _) in rows {
            query::check_deadline(deadline)?;
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let event = self.history_event(seq, &stream)?;
            let cost = query::event_size(&event)?;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(query::budget_failure(
                        &budget,
                        cost,
                        "first event exceeds history bytes",
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
            &stream.binding,
            page::PageFacts {
                h: stream.high,
                after: stream.after,
                last,
                bytes,
                stop,
                remaining: None,
            },
        )
    }
}
fn family_prefixes(f: HistoryFamily) -> Vec<&'static str> {
    match f {
        HistoryFamily::Identity => vec!["project.", "principal.", "profile.", "grant.", "alias."],
        HistoryFamily::Sessions => vec![
            "session.prepared",
            "session.activated",
            "session.ended",
            "session.revoked",
            "credential.",
        ],
        HistoryFamily::Messages => vec!["message."],
        HistoryFamily::Decisions => vec!["decision."],
        HistoryFamily::Turns => vec!["session.turn", "capture."],
        HistoryFamily::Processes => vec!["process."],
        HistoryFamily::WorkingState => vec!["working_state."],
        HistoryFamily::Cursors => vec!["cursor."],
        HistoryFamily::Effects => vec!["effect.", "integration."],
        HistoryFamily::Import => vec!["import.", "legacy."],
        HistoryFamily::Recovery => vec!["recovery.", "erasure.", "backup."],
    }
}

pub(super) fn normalize(query: &mut HistoryQuery) {
    let mut kinds = Vec::new();
    for kind in query.kinds.drain(..) {
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    kinds.sort_by_key(|kind| query::kind_name(*kind));
    query.kinds = kinds;
    let mut families = Vec::new();
    for family in query.families.drain(..) {
        if !families.contains(&family) {
            families.push(family);
        }
    }
    families.sort_by_key(|family| format!("{family:?}"));
    query.families = families;
}
