//! Search shares history's authorization, indexed candidates and fixed window.
use super::*;
use rusqlite::types::Value;

impl SqliteSnapshot {
    pub(super) fn read_search(
        &mut self,
        mut query: SearchQuery,
        budget: ReadBudget,
    ) -> StoreResult<SearchPage> {
        let deadline = query::deadline(&budget)?;
        if query.text.is_empty() || query.text.chars().count() > 512 {
            return Err(fail(
                StoreErrorCode::EventInvalid,
                "search text needs 1..512 characters",
            ));
        }
        history::normalize(&mut query.history);
        let stream = self.history_stream(&query.history, &budget, Some(&query.text))?;
        let mut params = stream.params.clone();
        // A limit bounds candidates, not just matches. An empty incomplete page
        // advances past checked nonmatches instead of pretending exhaustion.
        params.push(Value::Integer(i64::from(budget.page.limit.get()) + 1));
        let rows = self.query_seqs_before(&stream.sql, params, deadline)?;
        let needle = query.text.to_lowercase();
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = stream.after;
        let mut stop = StopReason::Exhausted;
        let mut erased = 0;
        let mut unreadable = 0;
        for (checked, (_, seq, _)) in rows.into_iter().enumerate() {
            query::check_deadline(deadline)?;
            if checked == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            // Retained erasure metadata is authoritative even if an old body
            // copy remains. Never reconstruct or search forgotten content.
            let forgotten: bool = self
                .db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM erased_fields WHERE event_seq=?)",
                    [seq],
                    |row| crate::sql_value::value(row, 0),
                )
                .map_err(|error| self.read_sql(error))?;
            if forgotten {
                erased += 1;
                last = seq as u64;
                continue;
            }
            let event = match self.history_event(seq, &stream) {
                Ok(event) => event,
                Err(error) if error.code == StoreErrorCode::ContentErased => {
                    erased += 1;
                    last = seq as u64;
                    continue;
                }
                Err(error) if candidate_unreadable(&error) => {
                    unreadable += 1;
                    last = seq as u64;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let cost = match query::event_size(&event) {
                Ok(cost) => cost,
                Err(error) if error.code == StoreErrorCode::ContentErased => {
                    erased += 1;
                    last = seq as u64;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if checked == 0 {
                    return Err(query::budget_failure(
                        &budget,
                        cost,
                        "first search candidate exceeds scan bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            if let Some((snippet, body_complete)) = snippet(&event.body, &needle)? {
                items.push(SearchHit {
                    event: event.header.event,
                    revision: event.revision,
                    snippet: StoredText::Present(snippet),
                    body_complete,
                });
            }
            last = seq as u64;
        }
        query::check_deadline(deadline)?;
        let page = self.page_with_unreadable(
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
            unreadable,
        )?;
        Ok(SearchPage { page, erased })
    }
}

fn candidate_unreadable(error: &StoreError) -> bool {
    // Payload/type failures can omit one candidate. Native SQLite failures,
    // missing tables, structural corruption and authorization/index drift still
    // fail the read instead of being laundered into an empty result.
    matches!(
        error.code,
        StoreErrorCode::Unreadable | StoreErrorCode::EventInvalid
    ) && !matches!(
        error.detail,
        StoreDetail::Sqlite { .. }
            | StoreDetail::Io {
                sqlite_extended_code: Some(_),
                ..
            }
    )
}

fn snippet(body: &EventBody<StoredText>, needle: &str) -> StoreResult<Option<(String, bool)>> {
    use EventBody::*;
    let fields = match body {
        MessageSent { body, .. } | WorkMessageSent { body, .. } => vec![body],
        SessionTurn { text, .. } | WorkingStateSet { text, .. } => vec![text],
        DecisionProposed {
            statement,
            rationale,
            ..
        } => {
            let mut fields = vec![statement];
            fields.extend(rationale.iter());
            fields
        }
        DecisionRejected { reason, .. }
        | DecisionRetracted { reason, .. }
        | SessionEnded { reason, .. }
        | SessionRevoked { reason, .. }
        | CredentialRevoked { reason, .. } => vec![reason],
        _ => Vec::new(),
    };
    let single = fields.len() == 1;
    for field in fields {
        let StoredText::Present(text) = field else {
            return Err(fail(
                StoreErrorCode::ContentErased,
                "search candidate text was erased",
            ));
        };
        if let Some(offset) = text.to_lowercase().find(needle) {
            // Lowercasing may change UTF-8 lengths (and even character counts).
            // Map the folded byte position back to an original character.
            let mut folded = 0;
            let mut matched = 0;
            for (index, ch) in text.chars().enumerate() {
                let length = ch.to_lowercase().map(char::len_utf8).sum::<usize>();
                if folded + length > offset {
                    matched = index;
                    break;
                }
                folded += length;
            }
            let length = text.chars().count();
            let start = matched.saturating_sub(80);
            let end = (start + 640).min(length);
            let snippet = text.chars().skip(start).take(end - start).collect();
            return Ok(Some((snippet, single && start == 0 && end == length)));
        }
    }
    Ok(None)
}
