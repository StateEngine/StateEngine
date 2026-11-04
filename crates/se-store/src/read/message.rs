use super::*;
use crate::sql_value::value;
use rusqlite::types::Value;
pub(super) type MarkRow = (i64, u64, Option<u64>, Option<u64>, Option<u64>);
type DeliveryRow = (i64, u64, Option<u64>, Option<u64>, Option<u64>, Vec<u8>);
impl SqliteSnapshot {
    /// Schema 3 adds delivery heads; it still needs the retained direct-mail
    /// projection and marks for decoding and subsequent recipient mutations.
    /// Preparing these finite sources preserves storage failure even when a
    /// maintained count or an empty delivery index would otherwise short-cut.
    pub(super) fn mail_source(&self) -> StoreResult<()> {
        self.db.prepare("SELECT d.sent_seq,m.message_seq FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE 0")
            .map_err(|error| self.read_sql(error))?;
        if self.info.schema_version >= 3 {
            self.db
                .prepare("SELECT sent_seq FROM message_deliveries WHERE 0")
                .map_err(|error| self.read_sql(error))?;
        }
        Ok(())
    }

    pub(super) fn read_messages(
        &self,
        query: MessageQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>> {
        self.read_messages_with_delivery(query, budget, false)
    }
    pub(super) fn read_messages_with_delivery(
        &self,
        query: MessageQuery,
        budget: ReadBudget,
        pending: bool,
    ) -> StoreResult<Page<MessageRecord>> {
        self.mail_source()?;
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let binding = format!(
            "live:mail:{}",
            codec::encode(&(
                &scope,
                &query.recipient,
                &query.sender,
                &query.kind,
                query.unread_only,
                query.full_body
            ))?
        );
        let binding = if pending {
            format!("delivery-pending:{binding}")
        } else {
            binding
        };
        let (h, after) = self.window(&budget, &binding, true)?;
        let id = |a: &Actor| {
            key(
                &self.db,
                a.kind(),
                a.wire(),
                if a.kind() == "human" { &[0] } else { &scope },
                false,
            )
        };
        let to = query.recipient.as_ref().map(id).transpose()?;
        let from = query.sender.as_ref().map(id).transpose()?;
        let own = match &self.scope.visibility {
            Visibility::SelfOnly(a) => Some(self.agent_bytes(a)?),
            _ => None,
        };
        let start = Instant::now();
        let deadline = start + budget.deadline;
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(|error| self.read_sql(error))?;
        let result: StoreResult<Vec<DeliveryRow>> = (|| {
            let mut rows = if let Some(own) = own {
                // A sent-or-received view is two index streams, not a broad page
                // followed by a visibility filter that can hide eligible rows.
                let mut sent = if from.as_ref().is_none_or(|v| v == &own) {
                    self.mail_stream(
                        &p,
                        to.as_deref(),
                        Some(&own),
                        &query,
                        h,
                        after,
                        &budget,
                        pending,
                    )?
                } else {
                    Vec::new()
                };
                let received = if to.as_ref().is_none_or(|v| v == &own) {
                    self.mail_stream(
                        &p,
                        Some(&own),
                        from.as_deref(),
                        &query,
                        h,
                        after,
                        &budget,
                        pending,
                    )?
                } else {
                    Vec::new()
                };
                sent.extend(received);
                sent
            } else {
                self.mail_stream(
                    &p,
                    to.as_deref(),
                    from.as_deref(),
                    &query,
                    h,
                    after,
                    &budget,
                    pending,
                )?
            };
            rows.sort_by_key(|r| r.0);
            rows.dedup_by_key(|r| r.0);
            rows.truncate(budget.page.limit.get() as usize + 1);
            Ok(rows)
        })();
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(|error| self.read_sql(error))?;
        let rows: Vec<DeliveryRow> = result?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (sent, revision, d, r, x, recipient) in rows {
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            if start.elapsed() >= budget.deadline {
                return Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "mail read deadline exhausted",
                ));
            }
            let mut message = self.message_at(sent, revision, d, r, x, Some(&recipient))?;
            if !query.full_body
                && let StoredText::Present(s) = &mut message.body
            {
                let end = s.char_indices().nth(400).map(|p| p.0).unwrap_or(s.len());
                if end < s.len() {
                    s.truncate(end);
                    message.body_complete = false
                }
            }
            let body = match &message.body {
                StoredText::Present(s) => codec::encode(s)?,
                StoredText::Erased { .. } => String::new(),
            };
            let metadata = codec::encode(&(
                &message.message,
                &message.event,
                &message.sender,
                &message.recipient,
                &message.work,
                &message.kind,
                &message.refs,
                &message.reply_to,
                message.body_complete,
            ))?;
            let cost = (body.len() + metadata.len()) as u64 + 1024;
            if cost + bytes > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    let mut e = fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "first complete mail item exceeds page bytes",
                    );
                    e.detail = StoreDetail::Budget {
                        allowed: u64::from(budget.page.max_bytes.get()),
                        required: Some(cost),
                    };
                    return Err(e);
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            last = sent as u64;
            items.push(message);
        }
        let remaining = if !pending
            && after == 0
            && query.unread_only
            && query.kind.is_none()
            && query.sender.is_none()
            && query.recipient.is_some()
            && match &self.scope.visibility {
                Visibility::SelfOnly(agent) => {
                    query.recipient.as_ref() == Some(&Actor::Agent(agent.clone()))
                }
                _ => true,
            } {
            let total = self.count_messages(query.clone())?;
            let remaining = total.checked_sub(items.len() as u64).ok_or_else(|| {
                fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "unread count is smaller than its eligible page",
                )
            })?;
            if stop == StopReason::Exhausted && remaining != 0 {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "unread count disagrees with exhausted mail query",
                ));
            }
            Some(remaining)
        } else {
            None
        };
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
    #[allow(
        clippy::too_many_arguments,
        reason = "One indexed mail stream binds scope, both optional actors, query and finite window/budget together."
    )]
    fn mail_stream(
        &self,
        p: &[u8],
        to: Option<&[u8]>,
        from: Option<&[u8]>,
        query: &MessageQuery,
        h: u64,
        after: u64,
        budget: &ReadBudget,
        pending: bool,
    ) -> StoreResult<Vec<DeliveryRow>> {
        let (mut statement, mut args) = mail_sql(
            p,
            to,
            from,
            query,
            h,
            after,
            // The single MIN aggregate pins SQLite's accompanying bare columns
            // to one matching delivery, including an unfiltered unread view.
            "d.sent_seq,d.revision,d.delivered_seq,d.read_seq,d.dismissed_seq,MIN(d.recipient_id)",
            self.info.schema_version,
        );
        if pending {
            statement.push_str(if self.info.schema_version >= 3 {
                " AND d.delivered_seq IS NULL"
            } else {
                " AND m.delivered_seq IS NULL"
            });
        }
        statement.push_str(" GROUP BY d.sent_seq ORDER BY d.sent_seq LIMIT ?");
        args.push(Value::Integer(i64::from(budget.page.limit.get()) + 1));
        let mut q = self
            .db
            .prepare(&statement)
            .map_err(|error| self.read_sql(error))?;
        q.query_map(rusqlite::params_from_iter(args), |r| {
            Ok((
                value(r, 0)?,
                value(r, 1)?,
                value(r, 2)?,
                value(r, 3)?,
                value(r, 4)?,
                value(r, 5)?,
            ))
        })
        .map_err(|error| self.read_sql(error))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::OperationInterrupted =>
            {
                fail(
                    StoreErrorCode::ReadIncomplete,
                    "mail SQL deadline exhausted",
                )
            }
            _ => sql(e),
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Keep the finite mail query and its supported schema together without passing snapshot authority."
)]
pub(super) fn mail_sql(
    p: &[u8],
    to: Option<&[u8]>,
    from: Option<&[u8]>,
    query: &MessageQuery,
    h: u64,
    after: u64,
    projection: &str,
    schema: u32,
) -> (String, Vec<Value>) {
    if schema < 3 {
        let projection = projection
            .replace("d.delivered_seq", "m.delivered_seq")
            .replace("d.read_seq", "m.read_seq")
            .replace("d.dismissed_seq", "m.dismissed_seq");
        return mail_legacy::sql(p, to, from, query, h, after, &projection);
    }
    let unread = query.unread_only && to.is_some();
    let index = if to.is_some() {
        "mail_recipient_seq"
    } else if from.is_some() {
        "mail_sender_seq"
    } else if query.kind.is_some() {
        "mail_kind_seq"
    } else {
        "mail_project_seq"
    };
    let mut statement = if unread {
        format!(
            "SELECT {projection} FROM message_deliveries d INDEXED BY mail_unread WHERE d.project_id=? AND d.read_seq IS NULL AND d.dismissed_seq IS NULL AND d.sent_seq>? AND d.sent_seq<=?"
        )
    } else {
        format!(
            "SELECT {projection} FROM message_deliveries d INDEXED BY {index} WHERE d.project_id=? AND d.sent_seq>? AND d.sent_seq<=?"
        )
    };
    let mut args = vec![
        Value::Blob(p.into()),
        Value::Integer(after as i64),
        Value::Integer(h as i64),
    ];
    if let Some(to) = to {
        statement.push_str(" AND d.recipient_id=?");
        args.push(Value::Blob(to.into()));
    }
    if let Some(from) = from {
        statement.push_str(" AND d.sender_id=?");
        args.push(Value::Blob(from.into()));
    }
    if let Some(kind) = &query.kind {
        statement.push_str(" AND d.message_kind=?");
        args.push(Value::Text(kind.clone()));
    }
    if query.unread_only && !unread {
        statement.push_str(" AND d.read_seq IS NULL AND d.dismissed_seq IS NULL");
    }
    if query.unread_only {
        statement.push_str(" AND d.superseded_by IS NULL");
    }
    (statement, args)
}
