use super::*;
use crate::sql_value::value;
impl SqliteSnapshot {
    pub(super) fn list_heads(
        &self,
        table: &str,
        first: &str,
        filter: &str,
        keys: Vec<rusqlite::types::Value>,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        let binding = format!(
            "live:{table}:{filter}:{}:{:?}",
            codec::encode(&self.scope.admission.scope)?,
            keys
        );
        let (h, after) = self.window(&budget, &binding, true)?;
        let mut params = keys;
        params.push(rusqlite::types::Value::Integer(
            i64::try_from(after).map_err(invalid)?,
        ));
        params.push(rusqlite::types::Value::Integer(
            i64::from(budget.page.limit.get()) + 1,
        ));
        let sql = format!(
            "SELECT revision,last_seq,{first} FROM {table} WHERE {filter} AND {first}>? ORDER BY {first} LIMIT ?"
        );
        let rows = self.query_seqs(&sql, params, &budget)?;
        let mut items = Vec::new();
        let mut bytes = 0u64;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (revision, seq, sort) in rows {
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let current = if table == "principals" {
                self.principal_metadata(seq)?
            } else {
                self.record(seq)?
            };
            let original = if first == "first_seq" && sort != seq as u64 {
                Some(Box::new(if table == "principals" {
                    self.principal_metadata(sort as i64)?
                } else {
                    self.record(sort as i64)?
                }))
            } else {
                None
            };
            let cost = event_size(&current)?
                + original
                    .as_ref()
                    .map(|e| event_size(e))
                    .transpose()?
                    .unwrap_or(0);
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "first head exceeds page bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            last = sort;
            items.push(ProjectionRecord {
                revision: codec::revision(revision)?,
                original,
                current,
            });
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
                remaining: None,
            },
        )
    }
    pub(super) fn query_seqs(
        &self,
        sql: &str,
        params: Vec<rusqlite::types::Value>,
        budget: &ReadBudget,
    ) -> StoreResult<Vec<(u64, i64, u64)>> {
        let deadline = Instant::now() + budget.deadline;
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(sql_error)?;
        let result = (|| {
            let mut q = self.db.prepare(sql).map_err(sql_error)?;
            q.query_map(rusqlite::params_from_iter(params), |r| {
                Ok((value(r, 0)?, value(r, 1)?, value(r, 2)?))
            })
            .map_err(sql_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_error)
        })();
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(sql_error)?;
        result
    }
    pub(super) fn read_history(
        &self,
        query: HistoryQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        let s = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let binding = format!(
            "history:{}:{:?}:{:?}:{:?}:{:?}",
            codec::encode(&s)?,
            self.scope.admission.actor,
            query.agent,
            query.session,
            (&query.kinds, &query.families)
        );
        let (h, mut after) = self.window(&budget, &binding, false)?;
        if let Some(position) = query.since {
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
        let mut sql = String::from(
            "SELECT entity_revision,seq,seq FROM events WHERE project_id IS ? AND seq>? AND seq<=? AND kind NOT IN ('runtime.owner','runtime.handover')",
        );
        let mut params = vec![
            p.map(rusqlite::types::Value::Blob)
                .unwrap_or(rusqlite::types::Value::Null),
            rusqlite::types::Value::Integer(after as i64),
            rusqlite::types::Value::Integer(h as i64),
        ];
        if let Some(agent) = query.agent {
            let a = self.agent_bytes(&agent)?;
            sql.push_str(" AND (actor_id=? OR seq IN (SELECT event_seq FROM turn_data WHERE project_id=? AND agent_id=?))");
            params.push(rusqlite::types::Value::Blob(a.clone()));
            params.push(rusqlite::types::Value::Blob(self.project_bytes()?));
            params.push(rusqlite::types::Value::Blob(a));
        }
        if let Some(session) = query.session {
            let k = key(&self.db, "session", session.as_str(), &s, false)?;
            sql.push_str(" AND session_id=?");
            params.push(rusqlite::types::Value::Blob(k));
        }
        if let Visibility::SelfOnly(agent) = &self.scope.visibility {
            let a = self.agent_bytes(agent)?;
            sql.push_str(" AND (actor_id=? OR seq IN (SELECT sent_seq FROM messages WHERE project_id=? AND recipient_id=?) OR seq IN (SELECT event_seq FROM turn_data WHERE project_id=? AND agent_id=?))");
            params.push(rusqlite::types::Value::Blob(a.clone()));
            params.push(rusqlite::types::Value::Blob(self.project_bytes()?));
            params.push(rusqlite::types::Value::Blob(a.clone()));
            params.push(rusqlite::types::Value::Blob(self.project_bytes()?));
            params.push(rusqlite::types::Value::Blob(a));
        }
        if !query.kinds.is_empty() {
            if query.kinds.len() > 52 {
                return Err(invalid("history kind limit"));
            }
            sql.push_str(" AND kind IN (");
            sql.push_str(&vec!["?"; query.kinds.len()].join(","));
            sql.push(')');
            for k in query.kinds {
                params.push(rusqlite::types::Value::Text(kind_name(k).into()));
            }
        }
        if !query.families.is_empty() {
            let mut prefixes = Vec::new();
            for f in query.families {
                prefixes.extend(family_prefixes(f))
            }
            sql.push_str(" AND (");
            sql.push_str(&vec!["kind LIKE ?"; prefixes.len()].join(" OR "));
            sql.push(')');
            for prefix in prefixes {
                params.push(rusqlite::types::Value::Text(format!("{prefix}%")));
            }
        }
        sql.push_str(" ORDER BY seq LIMIT ?");
        params.push(rusqlite::types::Value::Integer(
            i64::from(budget.page.limit.get()) + 1,
        ));
        let rows = self.query_seqs(&sql, params, &budget)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (_, seq, _) in rows {
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let e = self.record(seq)?;
            let cost = event_size(&e)?;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "first event exceeds history bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            last = seq as u64;
            items.push(e);
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
                remaining: None,
            },
        )
    }
}
fn sql_error(e: rusqlite::Error) -> Box<StoreError> {
    if matches!(&e,rusqlite::Error::SqliteFailure(c,_) if c.code==rusqlite::ErrorCode::OperationInterrupted)
    {
        fail(
            StoreErrorCode::ReadIncomplete,
            "SQLite read deadline/step budget exhausted",
        )
    } else {
        sql(e)
    }
}
pub(super) fn event_size(e: &StoredEvent) -> StoreResult<u64> {
    let body = crate::transaction::descriptor(&e.body, |t| match t {
        StoredText::Present(s) => Ok(s.clone()),
        StoredText::Erased { .. } => Err(fail(StoreErrorCode::ContentErased, "body was erased")),
    })?;
    let h = &e.header;
    let header = codec::encode(&(
        &h.event,
        &h.scope,
        &h.actor,
        &h.session,
        &h.origin,
        h.door,
        h.occurred_at_us,
        &h.cause,
        &h.supersedes,
    ))?;
    Ok((body.len() + header.len()) as u64 + 512)
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
fn kind_name(k: EventKind) -> &'static str {
    match k {
        EventKind::ProjectRegistered => "project.registered",
        EventKind::ProjectUpdated => "project.updated",
        EventKind::ProjectRemoved => "project.removed",
        EventKind::PrincipalRegistered => "principal.registered",
        EventKind::PrincipalRenamed => "principal.renamed",
        EventKind::AliasImported => "alias.imported",
        EventKind::ProfileSaved => "profile.saved",
        EventKind::GrantRecorded => "grant.recorded",
        EventKind::SessionPrepared => "session.prepared",
        EventKind::SessionActivated => "session.activated",
        EventKind::SessionEnded => "session.ended",
        EventKind::SessionRevoked => "session.revoked",
        EventKind::CredentialIssued => "credential.issued",
        EventKind::CredentialActivated => "credential.activated",
        EventKind::CredentialRevoked => "credential.revoked",
        EventKind::MessageSent => "message.sent",
        EventKind::MessageDelivered => "message.delivered",
        EventKind::MessageRead => "message.read",
        EventKind::MessageDismissed => "message.dismissed",
        EventKind::MessageSuperseded => "message.superseded",
        EventKind::DecisionProposed => "decision.proposed",
        EventKind::DecisionRatified => "decision.ratified",
        EventKind::DecisionRejected => "decision.rejected",
        EventKind::DecisionRetracted => "decision.retracted",
        EventKind::DecisionSuperseded => "decision.superseded",
        EventKind::SessionTurn => "session.turn",
        EventKind::CaptureSource => "capture.source",
        EventKind::CaptureProgress => "capture.progress",
        EventKind::CaptureFailed => "capture.failed",
        EventKind::CaptureSuppressed => "capture.suppressed",
        EventKind::ProcessRegistered => "process.registered",
        EventKind::ProcessTransition => "process.transition",
        EventKind::WorkingStateSet => "working_state.set",
        EventKind::CursorRecorded => "cursor.recorded",
        EventKind::CursorAcknowledged => "cursor.acknowledged",
        EventKind::EffectRequested => "effect.requested",
        EventKind::EffectOffered => "effect.offered",
        EventKind::EffectSettled => "effect.settled",
        EventKind::IntegrationRecorded => "integration.recorded",
        EventKind::RuntimeOwnerEstablished => "runtime.owner",
        EventKind::RuntimeHandoverRecorded => "runtime.handover",
        EventKind::BackupRecorded => "backup.recorded",
        EventKind::ImportStarted => "import.started",
        EventKind::ImportProgress => "import.progress",
        EventKind::ImportFinished => "import.finished",
        EventKind::ImportUnreadable => "import.unreadable",
        EventKind::LegacyRetained => "legacy.retained",
        EventKind::TurnErased => "turn.erased",
        EventKind::MessageErased => "message.erased",
        EventKind::ErasureRequested => "erasure.requested",
        EventKind::ErasureCompleted => "erasure.completed",
        EventKind::RecoveryRecorded => "recovery.recorded",
    }
}
