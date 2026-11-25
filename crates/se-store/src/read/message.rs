use super::*;
use crate::sql_value::value;
use rusqlite::types::Value;
pub(super) type MarkRow = (i64, u64, Option<u64>, Option<u64>, Option<u64>);
type DeliveryRow = (i64, u64, Option<u64>, Option<u64>, Option<u64>, Vec<u8>);
struct MailActors<'a> {
    project: &'a [u8],
    to: Option<&'a [u8]>,
    from: Option<&'a [u8]>,
    own: Option<&'a [u8]>,
}

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
        if self.info.schema_version >= 4 {
            self.db.prepare("SELECT quiet,wake_state,wake_event_seq,wake_code FROM message_deliveries WHERE 0")
                .map_err(|error| self.read_sql(error))?;
        }
        Ok(())
    }

    pub(super) fn read_messages(
        &mut self,
        query: MessageQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>> {
        self.read_messages_with_delivery(query, budget, false, false)
    }

    pub(super) fn read_messages_with_delivery(
        &mut self,
        query: MessageQuery,
        budget: ReadBudget,
        pending: bool,
        skip_count: bool,
    ) -> StoreResult<Page<MessageRecord>> {
        self.mail_source()?;
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let binding = format!(
            "live:mail:{}:{:?}",
            codec::encode(&(
                &scope,
                &query.recipient,
                &query.sender,
                &query.kind,
                query.unread_only,
                query.full_body
            ))?,
            query.direction
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
        let deadline = Instant::now() + budget.deadline;
        let rows = self.query_mail_delivery_rows(
            &MailActors {
                project: &p,
                to: to.as_deref(),
                from: from.as_deref(),
                own: own.as_deref(),
            },
            &query,
            (h, after),
            &budget,
            pending,
            deadline,
        )?;
        let (items, bytes, last, stop) = page::collect_page_rows(
            rows,
            &budget,
            after,
            deadline,
            "first complete mail item exceeds page bytes",
            |(sent, revision, d, r, x, recipient)| {
                let mut message = self.message_at(sent, revision, d, r, x, Some(&recipient))?;
                let cost = trim_and_cost_message(&mut message, query.full_body)?;
                Ok((message, cost, sent as u64))
            },
        )?;
        let remaining =
            self.unread_remaining_count(&query, pending, skip_count, after, items.len(), stop)?;
        self.page(
            items,
            &budget,
            &binding,
            page::PageFacts {
                h,
                // A newest-first continuation carries its frontier in the
                // cursor; the read window reports the shared floor.
                after: if query.direction == MailDirection::NewestFirst {
                    0
                } else {
                    after
                },
                last,
                bytes,
                stop,
                remaining,
            },
        )
    }

    fn query_mail_delivery_rows(
        &mut self,
        actors: &MailActors<'_>,
        query: &MessageQuery,
        (h, after): (u64, u64),
        budget: &ReadBudget,
        pending: bool,
        deadline: Instant,
    ) -> StoreResult<Vec<DeliveryRow>> {
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(|error| self.read_sql(error))?;
        let result: StoreResult<Vec<DeliveryRow>> = (|| {
            let stream = |to, from| {
                let window = MailWindow {
                    project: actors.project,
                    to,
                    from,
                    query,
                    high: h,
                    after,
                };
                self.mail_stream(window, budget, pending)
            };
            let mut rows = if let Some(own) = actors
                .own
                .filter(|own| actors.to != Some(*own) && actors.from != Some(*own))
            {
                // A sent-or-received view is two index streams, not a broad page
                // followed by a visibility filter that can hide eligible rows.
                let mut sent = if actors.from.is_none_or(|v| v == own) {
                    stream(actors.to, Some(own))?
                } else {
                    Vec::new()
                };
                if actors.to.is_none_or(|v| v == own) {
                    sent.extend(stream(Some(own), actors.from)?);
                }
                sent
            } else {
                // Either unscoped or an explicit self sender/recipient already bounds visibility.
                stream(actors.to, actors.from)?
            };
            if query.direction == MailDirection::NewestFirst {
                rows.sort_by_key(|r| i64::MAX - r.0);
            } else {
                rows.sort_by_key(|r| r.0);
            }
            rows.dedup_by_key(|r| r.0);
            rows.truncate(budget.page.limit.get() as usize + 1);
            Ok(rows)
        })();
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(|error| self.read_sql(error))?;
        result
    }

    fn unread_remaining_count(
        &mut self,
        query: &MessageQuery,
        pending: bool,
        skip_count: bool,
        after: u64,
        returned: usize,
        stop: StopReason,
    ) -> StoreResult<Option<u64>> {
        if pending
            || skip_count
            || after != 0
            || !query.unread_only
            || query.kind.is_some()
            || query.sender.is_some()
            || query.recipient.is_none()
            || !match &self.scope.visibility {
                Visibility::SelfOnly(agent) => {
                    query.recipient.as_ref() == Some(&Actor::Agent(agent.clone()))
                }
                _ => true,
            }
        {
            return Ok(None);
        }
        let total = self.count_messages(query.clone())?;
        let remaining = total.checked_sub(returned as u64).ok_or_else(|| {
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
        Ok(Some(remaining))
    }
    fn mail_stream(
        &self,
        window: MailWindow<'_>,
        budget: &ReadBudget,
        pending: bool,
    ) -> StoreResult<Vec<DeliveryRow>> {
        let (mut statement, mut args) = mail_sql(
            window,
            // The single MIN aggregate pins SQLite's accompanying bare columns
            // to one matching delivery, including an unfiltered unread view.
            "d.sent_seq,d.revision,d.delivered_seq,d.read_seq,d.dismissed_seq,MIN(d.recipient_id)",
            self.info.schema_version,
        );
        if pending {
            if self.info.schema_version >= 4 {
                // A prior committed notice can activate a quiet backlog. The
                // unread index includes both that backlog and ordinary mail.
                statement.push_str(" AND (d.quiet=0 OR d.wake_event_seq!=d.sent_seq)");
            }
            statement.push_str(if self.info.schema_version >= 3 {
                " AND d.delivered_seq IS NULL"
            } else {
                " AND m.delivered_seq IS NULL"
            });
        }
        if window.query.direction == MailDirection::NewestFirst {
            statement.push_str(" GROUP BY d.sent_seq ORDER BY d.sent_seq DESC LIMIT ?");
        } else {
            statement.push_str(" GROUP BY d.sent_seq ORDER BY d.sent_seq LIMIT ?");
        }
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

fn trim_and_cost_message(message: &mut MessageRecord, full_body: bool) -> StoreResult<u64> {
    if !full_body && let StoredText::Present(s) = &mut message.body {
        let end = s.char_indices().nth(400).map(|p| p.0).unwrap_or(s.len());
        if end < s.len() {
            s.truncate(end);
            message.body_complete = false;
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
    let notifications = message
        .notifications
        .iter()
        .map(|n| {
            n.recipient.wire().len() + n.state.len() + n.code.as_ref().map_or(0, String::len) + 256
        })
        .sum::<usize>();
    Ok((body.len() + metadata.len() + notifications) as u64 + 1024)
}

/// Keeps the finite mail query and its supported schema together without
/// passing snapshot authority.
pub(super) fn mail_sql(w: MailWindow<'_>, projection: &str, schema: u32) -> (String, Vec<Value>) {
    if schema < 3 {
        let projection = projection
            .replace("d.delivered_seq", "m.delivered_seq")
            .replace("d.read_seq", "m.read_seq")
            .replace("d.dismissed_seq", "m.dismissed_seq");
        return mail_legacy::sql(w, &projection);
    }
    let unread = w.query.unread_only && w.to.is_some();
    let index = if w.to.is_some() {
        "mail_recipient_seq"
    } else if w.from.is_some() {
        "mail_sender_seq"
    } else if w.query.kind.is_some() {
        "mail_kind_seq"
    } else {
        "mail_project_seq"
    };
    // A newest-first cursor carries the page frontier (its oldest returned
    // delivery); the next page resumes strictly below it from the floor.
    let (lower, upper_op, upper) = if w.query.direction == MailDirection::NewestFirst && w.after > 0
    {
        (0, "<", w.after)
    } else {
        (w.after, "<=", w.high)
    };
    let mut statement = if unread {
        format!(
            "SELECT {projection} FROM message_deliveries d INDEXED BY mail_unread WHERE d.project_id=? AND d.read_seq IS NULL AND d.dismissed_seq IS NULL AND d.sent_seq>? AND d.sent_seq{upper_op}?"
        )
    } else {
        format!(
            "SELECT {projection} FROM message_deliveries d INDEXED BY {index} WHERE d.project_id=? AND d.sent_seq>? AND d.sent_seq{upper_op}?"
        )
    };
    let mut args = vec![
        Value::Blob(w.project.into()),
        Value::Integer(lower as i64),
        Value::Integer(upper as i64),
    ];
    if let Some(to) = w.to {
        statement.push_str(" AND d.recipient_id=?");
        args.push(Value::Blob(to.into()));
    }
    if let Some(from) = w.from {
        statement.push_str(" AND d.sender_id=?");
        args.push(Value::Blob(from.into()));
    }
    if let Some(kind) = &w.query.kind {
        statement.push_str(" AND d.message_kind=?");
        args.push(Value::Text(kind.clone()));
    }
    if w.query.unread_only && !unread {
        statement.push_str(" AND d.read_seq IS NULL AND d.dismissed_seq IS NULL");
    }
    if w.query.unread_only {
        statement.push_str(" AND d.superseded_by IS NULL");
    }
    (statement, args)
}
