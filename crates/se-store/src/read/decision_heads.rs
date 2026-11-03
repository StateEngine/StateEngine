//! Current decision projections share membership across counts, pages and law.
use super::*;
use rusqlite::types::Value;

impl SqliteSnapshot {
    pub(super) fn read_decision_predecessor(
        &mut self,
        id: DecisionId,
    ) -> StoreResult<Read<DecisionId>> {
        match self.decision(id.clone())? {
            Read::Present { .. } => (),
            other => return Ok(other.map(|_| unreachable!())),
        }
        let project = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let target = key(&self.db, "decision", id.as_str(), &scope, false)?;
        let rows = self.query_seqs(
            "SELECT d.revision,d.last_seq,d.last_seq FROM decisions d INDEXED BY decisions_state JOIN decision_data transition ON transition.event_seq=d.last_seq WHERE d.project_id=? AND d.state='superseded' AND transition.replacement_id=? ORDER BY d.last_seq LIMIT 2",
            vec![Value::Blob(project), Value::Blob(target)],
            &metadata_budget()?,
        )?;
        match rows.as_slice() {
            [] => Ok(self.absent("committed decision predecessor")),
            [(_, seq, _)] => match self.decision_event(*seq, &id)?.body {
                EventBody::DecisionSuperseded { prior, .. } => Ok(Read::Present { value: prior }),
                _ => Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "decision predecessor is not a committed supersede",
                )),
            },
            _ => Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "multiple committed predecessors cannot be represented as one supersedes link",
            )),
        }
    }
    fn decision_filter(
        &self,
        query: DecisionQuery,
        governing: bool,
        history_visibility: bool,
    ) -> StoreResult<(String, Vec<Value>)> {
        let mut filter = String::from("project_id=?");
        let mut keys = vec![Value::Blob(self.project_bytes()?)];
        if governing {
            filter.push_str(" AND state='ratified'");
        } else if query.pending_only {
            filter.push_str(" AND state='proposed'");
        } else if !query.history {
            filter.push_str(" AND state IN ('proposed','ratified')");
        }
        if let Visibility::SelfOnly(agent) = &self.scope.visibility {
            // The closed transition graph makes superseded heads once-ratified;
            // retracted revision 3 is proposal -> ratify -> retract. A revision-2
            // withdrawal was never governing and remains private to its author.
            let law = if history_visibility {
                "state IN ('ratified','superseded') OR (state='retracted' AND revision=3)"
            } else {
                "state='ratified'"
            };
            filter.push_str(&format!(" AND ({law} OR EXISTS(SELECT 1 FROM events proposal WHERE proposal.seq=decisions.proposed_seq AND proposal.actor_id=?))"));
            keys.push(Value::Blob(self.agent_bytes(agent)?));
        }
        if let Some(id) = query.id {
            let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
            filter.push_str(" AND decision_id=?");
            keys.push(Value::Blob(key(
                &self.db,
                "decision",
                id.as_str(),
                &scope,
                false,
            )?));
        }
        Ok((filter, keys))
    }
    /// This narrow decision reader may read another agent's proposal only
    /// through a current or once-governing head. Generic event visibility stays intact.
    pub(super) fn decision_event(&self, seq: i64, id: &DecisionId) -> StoreResult<StoredEvent> {
        let event = load_event(&self.db, seq, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let target = key(&self.db, "decision", id.as_str(), &scope, false)?;
        let same = |id: &DecisionId| -> StoreResult<bool> {
            Ok(key(&self.db, "decision", id.as_str(), &scope, false)? == target)
        };
        let related = match &event.body {
            EventBody::DecisionProposed { decision, .. }
            | EventBody::DecisionRatified { decision, .. }
            | EventBody::DecisionRejected { decision, .. }
            | EventBody::DecisionRetracted { decision, .. } => same(decision)?,
            EventBody::DecisionSuperseded {
                prior, replacement, ..
            } => same(prior)? || same(replacement)?,
            _ => false,
        };
        if event.header.scope != self.scope.admission.scope || !related {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "decision event differs from admitted project or target",
            ));
        }
        let (filter, keys) = self.decision_filter(
            DecisionQuery {
                id: Some(id.clone()),
                pending_only: false,
                history: true,
            },
            false,
            true,
        )?;
        let visible: bool = self
            .db
            .query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM decisions WHERE {filter})"),
                rusqlite::params_from_iter(keys),
                |row| crate::sql_value::value(row, 0),
            )
            .map_err(|error| self.read_sql(error))?;
        if !visible {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "decision is outside admitted visibility",
            ));
        }
        Ok(event)
    }
    pub(super) fn read_decision_rows(
        &self,
        query: DecisionQuery,
        governing: bool,
        budget: ReadBudget,
    ) -> StoreResult<Page<Read<ProjectionRecord>>> {
        let deadline = Instant::now() + budget.deadline;
        let selectors = format!("{query:?}:{governing}");
        let history_visibility = query.history;
        let (filter, keys) = self.decision_filter(query, governing, history_visibility)?;
        let binding = format!("live:decision-heads:{selectors}:{filter}:{keys:?}");
        let (h, after) = self.window(&budget, &binding, true)?;
        let mut params = keys.clone();
        params.extend([
            Value::Integer(after as i64),
            Value::Integer(i64::from(budget.page.limit.get()) + 1),
        ]);
        let rows = self.query_seqs(
            &format!("SELECT revision,last_seq,proposed_seq FROM decisions WHERE {filter} AND last_seq>? ORDER BY last_seq LIMIT ?"),
            params,
            &budget,
        )?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (revision, seq, proposed) in rows {
            if Instant::now() >= deadline {
                return Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "decision head read deadline exhausted",
                ));
            }
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let head = match self.decision_projection(revision, seq, proposed) {
                Ok(head) => Read::Present { value: head },
                Err(error)
                    if matches!(
                        error.code,
                        StoreErrorCode::Unreadable
                            | StoreErrorCode::EventInvalid
                            | StoreErrorCode::ProjectionInconsistent
                            | StoreErrorCode::ContentErased
                    ) =>
                {
                    Read::Unreadable {
                        source: "decision head".into(),
                        reason: error.cause,
                        error: None,
                    }
                }
                Err(error) => return Err(error),
            };
            let cost = match &head {
                Read::Present { value } => {
                    query::event_size(&value.current)?
                        + value
                            .original
                            .as_ref()
                            .map(|event| query::event_size(event))
                            .transpose()?
                            .unwrap_or(0)
                }
                Read::Unreadable { source, reason, .. } => (source.len() + reason.len()) as u64,
                _ => unreachable!("decision page loads only present or unreadable heads"),
            };
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "first complete decision head exceeds page bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            last = seq as u64;
            items.push(head);
        }
        let remaining = if stop != StopReason::Exhausted {
            let mut keys = keys;
            keys.push(Value::Integer(last as i64));
            let mut count_budget = budget.clone();
            count_budget.deadline = deadline.saturating_duration_since(Instant::now());
            if count_budget.deadline.is_zero() {
                return Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "decision head count deadline exhausted",
                ));
            }
            Some(
                self.query_seqs(
                    &format!("SELECT count(*),0,0 FROM decisions WHERE {filter} AND last_seq>?"),
                    keys,
                    &count_budget,
                )?
                .first()
                .ok_or_else(|| {
                    fail(
                        StoreErrorCode::ProjectionInconsistent,
                        "decision head count missing",
                    )
                })?
                .0,
            )
        } else {
            None
        };
        if Instant::now() >= deadline {
            return Err(fail(
                StoreErrorCode::ReadIncomplete,
                "decision head read deadline exhausted",
            ));
        }
        self.page(
            items,
            &budget,
            &binding,
            page::PageFacts {
                h,
                after,
                last,
                bytes,
                stop,
                remaining,
            },
        )
    }
    fn decision_projection(
        &self,
        revision: u64,
        seq: i64,
        proposed: u64,
    ) -> StoreResult<ProjectionRecord> {
        let original = load_event(&self.db, proposed as i64, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        let EventBody::DecisionProposed { decision: id, .. } = &original.body else {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "decision head has no original proposal",
            ));
        };
        Ok(ProjectionRecord {
            revision: codec::revision(revision)?,
            current: self.decision_event(seq, id)?,
            original: if proposed != seq as u64 {
                Some(Box::new(self.decision_event(proposed as i64, id)?))
            } else {
                None
            },
        })
    }
    pub(super) fn read_decision_heads(
        &self,
        query: DecisionQuery,
        governing: bool,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        let page = self.read_decision_rows(query, governing, budget)?;
        let window = page.window().clone();
        let next = page.next().cloned();
        let items = page
            .into_items()
            .into_iter()
            .map(|head| match head {
                Read::Present { value } => Ok(value),
                Read::Unreadable { source, reason, .. } => Err(fail(
                    StoreErrorCode::Unreadable,
                    format!("{source}: {reason}"),
                )),
                _ => unreachable!("decision page loads only present or unreadable heads"),
            })
            .collect::<StoreResult<Vec<_>>>()?;
        Page::new(items, window, next).map_err(invalid)
    }
    pub(super) fn count_decision_heads(&self, pending_only: bool) -> StoreResult<u64> {
        let (filter, keys) = self.decision_filter(
            DecisionQuery {
                id: None,
                pending_only,
                history: true,
            },
            false,
            false,
        )?;
        self.query_seqs(
            &format!("SELECT count(*),0,0 FROM decisions WHERE {filter}"),
            keys,
            &metadata_budget()?,
        )?
        .first()
        .map(|row| row.0)
        .ok_or_else(|| {
            fail(
                StoreErrorCode::ProjectionInconsistent,
                "decision count is unavailable",
            )
        })
    }
}
fn metadata_budget() -> StoreResult<ReadBudget> {
    Ok(ReadBudget {
        page: se_types::PageRequest {
            after: None,
            limit: std::num::NonZeroU32::new(2)
                .ok_or_else(|| invalid("positive decision query limit"))?,
            max_bytes: std::num::NonZeroU32::new(1024)
                .ok_or_else(|| invalid("positive decision query byte budget"))?,
        },
        deadline: std::time::Duration::from_secs(5),
    })
}
