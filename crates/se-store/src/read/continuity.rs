//! Bounded reads for a session's continuity packet: the newest turns, the
//! governing decisions and exact decision counts. No full-history scan.
use super::*;
impl SqliteSnapshot {
    /// The newest turns after `since`, oldest first, with the older turns
    /// this bounded tail left out counted exactly in `omitted_before`.
    pub(super) fn read_recent_turns(
        &self,
        agent: AgentId,
        since: Option<StorePosition>,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        if budget.page.after.is_some() {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "recent turns take a since position, never a page continuation",
            ));
        }
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        let binding = format!("history:recent-turns:{}", agent.as_str());
        let (h, _) = self.window(&budget, &binding, false)?;
        let floor = match &since {
            None => 0,
            Some(position) if position.belongs(&self.info) && position.sequence() <= h => {
                position.sequence()
            }
            Some(_) => {
                return Err(fail(
                    StoreErrorCode::CursorStale,
                    "since position is outside this store, incarnation or snapshot",
                ));
            }
        };
        let params = |extra: i64| {
            vec![
                rusqlite::types::Value::Blob(p.clone()),
                rusqlite::types::Value::Blob(a.clone()),
                rusqlite::types::Value::Integer(floor as i64),
                rusqlite::types::Value::Integer(h as i64),
                rusqlite::types::Value::Integer(extra),
            ]
        };
        let rows = self.query_seqs(
            "SELECT e.entity_revision,t.event_seq,t.event_seq FROM turn_data t INDEXED BY turn_data_agent_seq JOIN events e ON e.seq=t.event_seq WHERE t.project_id=? AND t.agent_id=? AND t.event_seq>? AND t.event_seq<=? ORDER BY t.event_seq DESC LIMIT ?",
            params(i64::from(budget.page.limit.get())),
            &budget,
        )?;
        let mut items = Vec::new();
        let mut bytes = 0u64;
        let mut stop = StopReason::Exhausted;
        for (_, seq, _) in rows {
            let e = self.record(seq)?;
            let cost = query::event_size(&e)?;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "the newest turn exceeds page bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            items.push((seq, e));
        }
        items.reverse();
        let oldest = items.first().map(|(seq, _)| *seq as u64);
        let newest = items.last().map(|(seq, _)| *seq as u64).unwrap_or(floor);
        // Exact count of the older turns the tail left out, from the same index.
        let older: u64 = match oldest {
            None => 0,
            Some(oldest) => self
                .db
                .query_row(
                    "SELECT count(*) FROM turn_data INDEXED BY turn_data_agent_seq WHERE project_id=? AND agent_id=? AND event_seq>? AND event_seq<?",
                    rusqlite::params![p, a, floor as i64, oldest as i64],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(|error| self.read_sql(error))?,
        };
        let omitted_before = match std::num::NonZeroU64::new(older) {
            None => Omission::None,
            Some(count) => {
                if stop == StopReason::Exhausted {
                    stop = StopReason::ItemLimit;
                }
                Omission::Known {
                    count,
                    reason: if stop == StopReason::ByteLimit {
                        OmissionReason::Budget
                    } else {
                        OmissionReason::Limit
                    },
                }
            }
        };
        let window = Window::new(WindowFields {
            source: Source::Store {
                store: self.info.id.clone(),
                project: match &self.scope.admission.scope {
                    Scope::Project(p) => Some(p.clone()),
                    _ => None,
                },
            },
            from: Sequence::new(floor).map_err(invalid)?,
            to: Sequence::new(h).map_err(invalid)?,
            start_cursor: None,
            end_cursor: Some(self.cursor(&binding, h, newest)?),
            returned: items.len() as u64,
            limit: budget.page.limit,
            bytes,
            max_bytes: budget.page.max_bytes,
            omitted_before,
            omitted_after: Omission::None,
            unreadable: 0,
            stop_reason: stop,
        })
        .map_err(invalid)?;
        Page::new(items.into_iter().map(|(_, e)| e).collect(), window, None).map_err(invalid)
    }
    /// Current ratified decision heads, the project's governing rulings.
    pub(super) fn read_governing_decisions(
        &self,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        let p = self.project_bytes()?;
        self.list_heads(
            "decisions",
            "last_seq",
            "project_id=? AND state='ratified'",
            vec![rusqlite::types::Value::Blob(p)],
            budget,
        )
    }
    /// Exact decision heads in this snapshot, all or only pending proposals.
    pub(super) fn read_decision_count(&self, pending_only: bool) -> StoreResult<u64> {
        let p = self.project_bytes()?;
        self.db
            .query_row(
                if pending_only {
                    "SELECT count(*) FROM decisions WHERE project_id=? AND state='proposed'"
                } else {
                    "SELECT count(*) FROM decisions WHERE project_id=?"
                },
                [&p],
                |r| crate::sql_value::value(r, 0),
            )
            .map_err(|error| self.read_sql(error))
    }
}
