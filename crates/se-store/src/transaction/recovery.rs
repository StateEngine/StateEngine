use super::*;
use std::{path::Path, time::Duration};
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Uncertain {
    scope: Scope,
    actor: Actor,
    operation: PendingOperation,
}
impl Uncertain {
    pub(super) fn annotate(&self, error: &mut StoreError) {
        error.cause.push_str(&format!(
            "; unresolved {:?} for {:?} / {:?}",
            self.operation, self.scope, self.actor
        ));
        if let PendingOperation::CallerKey(key) = &self.operation {
            error.detail = StoreDetail::Request {
                scope: self.scope.clone(),
                actor: self.actor.clone(),
                key: key.clone(),
                original_event: None,
            };
        }
    }
    pub(super) fn from_batch(batch: &AtomicBatch) -> Self {
        Self {
            scope: batch.admission.scope.clone(),
            actor: batch.admission.actor.clone(),
            operation: match &batch.request {
                Some(request) => PendingOperation::CallerKey(request.key.clone()),
                None => PendingOperation::NaturalEvents(
                    batch
                        .events
                        .iter()
                        .map(|e| e.header.event.clone())
                        .collect(),
                ),
            },
        }
    }
}
impl Engine {
    pub(crate) fn indeterminate(&self) -> Vec<PendingOperation> {
        self.pending.iter().map(|p| p.operation.clone()).collect()
    }
    pub(crate) fn require_resolved(&self) -> StoreResult<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        Err(fail(
            StoreErrorCode::CommitOutcomeUnknown,
            format!(
                "unresolved commit acknowledgements: {:?}; retry these original caller keys or natural event IDs before clean close",
                self.indeterminate()
            ),
        ))
    }
    pub(super) fn rollback_confirmed(&mut self) -> StoreResult<()> {
        if !self.db.is_autocommit()
            && let Err(error) = self.db.execute_batch("ROLLBACK")
        {
            self.poisoned = true;
            return Err(sql(error));
        }
        if !self.db.is_autocommit() {
            self.poisoned = true;
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "whole-group rollback is not confirmed",
            ));
        }
        Ok(())
    }
    /// Reconnect only under the same native custody, with a bounded independent
    /// readback of the header, identity and pending receipt members.
    pub(crate) fn reopen(
        &mut self,
        path: &Path,
        timeout: Duration,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<()> {
        if !self.poisoned {
            return Ok(());
        }
        if !matches!(
            lease.files().readback(path)?,
            se_types::Read::Present { .. }
        ) {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "writer reopen has no protected state-file readback",
            ));
        }
        let next = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sql)?;
        // Opening a handle does not acquire a write lock. Close the failed
        // connection before setting pragmas or attempting journal recovery.
        let old = std::mem::replace(&mut self.db, next);
        drop(old);
        connection::configure(&self.db, true, timeout)?;
        let start = Instant::now();
        let limit = timeout
            .max(Duration::from_millis(100))
            .min(Duration::from_secs(5));
        self.db
            .progress_handler(1000, Some(move || start.elapsed() >= limit))
            .map_err(sql)?;
        let checked = (|| {
            self.db.execute_batch("BEGIN").map_err(sql)?;
            let info = connection::info(&self.db)?;
            let identity = connection::validate_lease(&info, lease, self.identity.mode)?;
            if identity.store != self.identity.store
                || identity.generation != self.identity.generation
                || identity.mode != self.identity.mode
                || info.state != StoreState::Ready
            {
                return Err(fail(
                    StoreErrorCode::GenerationChanged,
                    "writer reopen identity/readiness differs",
                ));
            }
            for pending in &self.pending {
                match &pending.operation {
                    PendingOperation::CallerKey(key) => {
                        let scope = scope_key(&self.db, &pending.scope, false)?;
                        let actor = key_bytes(&self.db, &pending.actor, &scope)?;
                        let op:Option<Vec<u8>>=self.db.query_row(
                            "SELECT operation_id FROM operations WHERE scope_key=? AND actor_id=? AND request_key=? AND erased=0",
                            rusqlite::params![scope,actor,key.as_str()],|r|r.get(0)).optional().map_err(sql)?;
                        if let Some(op) = op {
                            receipt(&self.db, &op, &info, Some(key.clone()))?;
                        }
                    }
                    PendingOperation::NaturalEvents(events) => {
                        let scope = scope_key(&self.db, &pending.scope, false)?;
                        for event in events {
                            let id = key(&self.db, "event", event.as_str(), &scope, false)?;
                            let seq: Option<i64> = self
                                .db
                                .query_row("SELECT seq FROM events WHERE event_id=?", [id], |r| {
                                    r.get(0)
                                })
                                .optional()
                                .map_err(sql)?;
                            if let Some(seq) = seq {
                                crate::read::load_event(&self.db, seq, &info)?;
                            }
                        }
                    }
                }
            }
            Ok(())
        })();
        let rollback = self.db.execute_batch("ROLLBACK").map_err(sql);
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(sql)?;
        checked?;
        rollback?;
        if !matches!(
            lease.files().readback(path)?,
            se_types::Read::Present { .. }
        ) {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "protected state-file readback changed during writer reopen",
            ));
        }
        // The database is writable again, but original callers must still
        // resolve their acknowledgements. A successful retry removes its entry.
        self.poisoned = false;
        Ok(())
    }
}
fn key_bytes(c: &Connection, actor: &Actor, scope: &[u8]) -> StoreResult<Vec<u8>> {
    key(
        c,
        actor.kind(),
        actor.wire(),
        if actor.kind() == "human" { &[0] } else { scope },
        false,
    )
}
