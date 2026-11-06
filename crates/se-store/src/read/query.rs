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
        let deadline = deadline(&budget)?;
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
        let rows = self.query_seqs_before(&sql, params, deadline)?;
        let mut items = Vec::new();
        let mut bytes = 0u64;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (revision, seq, sort) in rows {
            check_deadline(deadline)?;
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let current = if table == "principals" {
                self.principal_metadata(seq)?
            } else {
                self.record(seq)?
            };
            let original = if matches!(first, "first_seq" | "requested_seq") && sort != seq as u64 {
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
                    return Err(budget_failure(
                        &budget,
                        cost,
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
        check_deadline(deadline)?;
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
        self.query_seqs_before(sql, params, deadline(budget)?)
    }
    pub(super) fn query_seqs_before(
        &self,
        sql: &str,
        params: Vec<rusqlite::types::Value>,
        deadline: Instant,
    ) -> StoreResult<Vec<(u64, i64, u64)>> {
        check_deadline(deadline)?;
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(|error| self.read_sql(error))?;
        let result = (|| {
            let mut q = self.db.prepare(sql).map_err(|error| self.read_sql(error))?;
            q.query_map(rusqlite::params_from_iter(params), |r| {
                Ok((value(r, 0)?, value(r, 1)?, value(r, 2)?))
            })
            .map_err(|error| self.read_sql(error))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| self.read_sql(error))
        })();
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(|error| self.read_sql(error))?;
        let rows = result?;
        check_deadline(deadline)?;
        Ok(rows)
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
pub(super) fn kind_name(k: EventKind) -> &'static str {
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
        EventKind::WorkMessageSent => "message.work_sent",
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
        EventKind::CaptureVerified => "capture.verified",
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

pub(super) fn check_deadline(deadline: Instant) -> StoreResult<()> {
    if Instant::now() >= deadline {
        return Err(fail(
            StoreErrorCode::ReadIncomplete,
            "read deadline elapsed",
        ));
    }
    Ok(())
}

pub(super) fn deadline(budget: &ReadBudget) -> StoreResult<Instant> {
    if budget.deadline.is_zero() || budget.deadline > std::time::Duration::from_secs(5) {
        return Err(fail(
            StoreErrorCode::EventInvalid,
            "read deadline must be positive and at most 5 seconds",
        ));
    }
    Ok(Instant::now() + budget.deadline)
}

pub(super) fn budget_failure(budget: &ReadBudget, required: u64, cause: &str) -> Box<StoreError> {
    let mut error = fail(StoreErrorCode::ReadBudgetTooSmall, cause);
    error.detail = StoreDetail::Budget {
        allowed: u64::from(budget.page.max_bytes.get()),
        required: Some(required),
    };
    error
}
