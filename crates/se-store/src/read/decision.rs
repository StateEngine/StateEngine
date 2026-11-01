//! Exact immutable decision reads; no history enumeration or projection repair.
use super::*;

fn read_error(error: rusqlite::Error) -> Box<StoreError> {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted) {
        fail(
            StoreErrorCode::ReadIncomplete,
            "decision read deadline exhausted",
        )
    } else {
        sql(error)
    }
}
fn relates(event: &StoredEvent, id: &DecisionId) -> bool {
    match &event.body {
        EventBody::DecisionProposed { decision, .. } => decision == id,
        EventBody::DecisionRatified { decision, .. }
        | EventBody::DecisionRejected { decision, .. }
        | EventBody::DecisionRetracted { decision, .. } => decision == id,
        EventBody::DecisionSuperseded {
            prior, replacement, ..
        } => prior == id || replacement == id,
        _ => false,
    }
}
impl SqliteSnapshot {
    pub(super) fn read_decision_transitions(
        &self,
        id: DecisionId,
        budget: ReadBudget,
    ) -> StoreResult<Read<Page<StoredEvent>>> {
        let binding = format!("history:decision-transitions:{}", id.as_str());
        let (h, after) = self.window(&budget, &binding, false)?;
        let deadline = Instant::now() + budget.deadline;
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(read_error)?;
        let result = (|| {
            let project = self.project_bytes()?;
            let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
            let decision = key(&self.db, "decision", id.as_str(), &scope, false)?;
            let proposed: Option<i64> = self.db.query_row(
                "SELECT event_seq FROM decision_data WHERE project_id=? AND decision_id=? AND state='proposed' AND event_seq<=? ORDER BY event_seq LIMIT 1",
                crate::sql_value::sql_params![project, decision, h],
                |row| crate::sql_value::value(row, 0),
            ).optional().map_err(read_error)?;
            let Some(proposed) = proposed else {
                let local: bool = self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM decision_data WHERE project_id=? AND decision_id=? AND event_seq<=?) OR EXISTS(SELECT 1 FROM decisions WHERE project_id=? AND decision_id=? AND proposed_seq<=?)",
                    crate::sql_value::sql_params![project, decision, h, project, decision, h],
                    |row| crate::sql_value::value(row, 0),
                ).map_err(read_error)?;
                if local {
                    return Err(fail(
                        StoreErrorCode::ProjectionInconsistent,
                        "known decision has no immutable proposal",
                    ));
                }
                let excluded: bool = self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM decision_data WHERE decision_id=? AND event_seq<=?)",
                    crate::sql_value::sql_params![decision, h],
                    |row| crate::sql_value::value(row, 0),
                ).map_err(read_error)?;
                let excluded = excluded || (canonical(id.as_str()).is_none() && self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM identities i JOIN decision_data d ON d.decision_id=i.storage_key WHERE i.kind='decision' AND i.wire_id=? AND d.event_seq<=?)",
                    crate::sql_value::sql_params![id.as_str(), h],
                    |row| crate::sql_value::value::<bool>(row, 0),
                ).map_err(read_error)?);
                if excluded {
                    return Err(fail(
                        StoreErrorCode::ScopeMismatch,
                        "decision is outside admitted scope",
                    ));
                }
                return Ok(self.absent("decision transitions"));
            };
            let original = self.record(proposed)?;
            if original.header.scope != self.scope.admission.scope
                || !matches!(&original.body, EventBody::DecisionProposed { decision, .. } if decision == &id)
            {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "decision proposal lookup differs from its immutable event",
                ));
            }
            let rows = {
                let mut statement = self.db.prepare(
                    "SELECT event_seq FROM decision_data WHERE project_id=? AND (decision_id=? OR replacement_id=?) AND event_seq>? AND event_seq<=? ORDER BY event_seq LIMIT ?",
                ).map_err(read_error)?;
                statement
                    .query_map(
                        crate::sql_value::sql_params![
                            project,
                            decision,
                            decision,
                            after,
                            h,
                            i64::from(budget.page.limit.get()) + 1
                        ],
                        |row| crate::sql_value::value::<i64>(row, 0),
                    )
                    .map_err(read_error)?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(read_error)?
            };
            let mut items = Vec::new();
            let mut bytes = 0;
            let mut last = after;
            let mut stop = StopReason::Exhausted;
            for seq in rows {
                if Instant::now() >= deadline {
                    return Err(fail(
                        StoreErrorCode::ReadIncomplete,
                        "decision read deadline exhausted",
                    ));
                }
                if items.len() == budget.page.limit.get() as usize {
                    stop = StopReason::ItemLimit;
                    break;
                }
                let event = self.record(seq)?;
                if event.header.scope != self.scope.admission.scope || !relates(&event, &id) {
                    return Err(fail(
                        StoreErrorCode::ProjectionInconsistent,
                        "decision transition lookup differs from its immutable event",
                    ));
                }
                let cost = query::event_size(&event)?;
                if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                    if items.is_empty() {
                        return Err(fail(
                            StoreErrorCode::ReadBudgetTooSmall,
                            "first complete decision event exceeds page bytes",
                        ));
                    }
                    stop = StopReason::ByteLimit;
                    break;
                }
                bytes += cost;
                last = seq as u64;
                items.push(event);
            }
            let page = self.page(
                items,
                &budget,
                &binding,
                page::PageFacts {
                    h,
                    after,
                    last,
                    bytes,
                    stop,
                    remaining: None,
                },
            )?;
            Ok(Read::Present { value: page })
        })();
        let result = if Instant::now() >= deadline {
            match result {
                Ok(_) => Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "decision read deadline exhausted",
                )),
                Err(mut error) => {
                    error.code = StoreErrorCode::ReadIncomplete;
                    error.cause = format!("decision read deadline exhausted: {}", error.cause);
                    Err(error)
                }
            }
        } else {
            result
        };
        let cleanup = self
            .db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(read_error);
        // Preserve the original read failure even if retiring its deadline hook fails.
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                cleanup?;
                Ok(value)
            }
        }
    }
}
