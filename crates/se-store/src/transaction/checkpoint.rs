//! WAL maintenance state shared by the commit path and the background task.
//! COMMIT still establishes every receipt; maintenance never relabels its result.
use super::*;
use crate::backup_context::MAX_WAL_BYTES;
use std::sync::{Arc, Condvar, Mutex};

const SOFT_FRAMES: i64 = 256;
/// The restart never waits longer than this for a reader to leave; a busy
/// restart is retried after more growth, and the cutoff stays the backstop.
const RESTART_WAIT: Duration = Duration::from_millis(10);
/// Growth (about 4 MiB) between background copy requests and between restart
/// retries. The pacing is by growth, not progress, so a pinned reader or a
/// backup costs one attempt per step instead of one per commit.
const STEP_FRAMES: i64 = 1024;
/// Only the background task holds the gate while the writer waits for it.
const GATE_HELD: &str = "another checkpoint exceeded this connection's busy timeout";

#[derive(Default)]
pub(crate) struct Schedule {
    pending: bool,
    copy: bool,
    /// Log length at the last copy request and at the last busy restart.
    copy_mark: i64,
    restart_mark: i64,
    pub gate: Gate,
}
/// SQLite does not invoke the busy handler when another checkpoint owns its
/// checkpoint lock. Coordinate our two connections before entering SQLite;
/// ordinary commits and WAL accounting never acquire this gate.
#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<(Mutex<bool>, Condvar)>);
pub(crate) struct Permit<'a> {
    gate: &'a Gate,
}
impl Gate {
    pub(crate) fn acquire(&self, timeout: Duration) -> StoreResult<Permit<'_>> {
        let deadline = Instant::now() + timeout;
        let (lock, condition) = &*self.0;
        let mut active = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while *active {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(fail(StoreErrorCode::Busy, GATE_HELD));
            }
            active = condition
                .wait_timeout(active, left)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        *active = true;
        Ok(Permit { gate: self })
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let (lock, condition) = &*self.gate.0;
        *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        condition.notify_one();
    }
}
#[derive(Debug)]
pub(crate) struct Wal {
    pub log: i64,
    pub done: i64,
    pub bytes: u64,
}
/// Frame accounting from one connection's view. The WAL index is shared, so
/// every connection's NOOP reports the same log/done/bytes: done == log means
/// every frame is in the main database and no reader pins an older snapshot.
pub(crate) fn probe(db: &Connection) -> StoreResult<Wal> {
    let (log, done) = db
        .query_row("PRAGMA wal_checkpoint(NOOP)", [], |r| {
            Ok((
                crate::sql_value::value::<i64>(r, 1)?,
                crate::sql_value::value::<i64>(r, 2)?,
            ))
        })
        .map_err(sql)?;
    if log == -1 && done == -1 {
        return Ok(Wal {
            log,
            done,
            bytes: 0,
        });
    }
    if log < 0 || done < 0 || done > log {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "WAL accounting returned invalid frame counts",
        ));
    }
    let page: u64 = db
        .query_row("PRAGMA page_size", [], |r| crate::sql_value::value(r, 0))
        .map_err(sql)?;
    let bytes = (log as u64)
        .checked_mul(
            page.checked_add(24)
                .ok_or_else(|| invalid("WAL page size overflow"))?,
        )
        .and_then(|n| n.checked_add(32))
        .ok_or_else(|| invalid("WAL size overflow"))?;
    Ok(Wal { log, done, bytes })
}
pub(crate) fn wal_checkpoint(db: &Connection, mode: &str) -> StoreResult<(i64, i64, i64)> {
    let statement = format!("PRAGMA wal_checkpoint({mode})");
    db.query_row(statement.as_str(), [], |r| {
        Ok((
            crate::sql_value::value::<i64>(r, 0)?,
            crate::sql_value::value::<i64>(r, 1)?,
            crate::sql_value::value::<i64>(r, 2)?,
        ))
    })
    .map_err(sql)
}
fn classify_checkpoint(
    result: StoreResult<(i64, i64, i64)>,
    hard: bool,
) -> Option<Box<StoreError>> {
    match result {
        Ok((_, log, done)) if (log != -1 || done != -1) && (log < 0 || done < 0 || done > log) => {
            Some(fail(
                StoreErrorCode::Unreadable,
                "WAL checkpoint returned invalid frame counts",
            ))
        }
        Ok((0, log, done)) if log == done && (!hard || log == 0) => None,
        Ok(_) => Some(fail(
            StoreErrorCode::Busy,
            "committed checkpoint has pending frames",
        )),
        Err(error) => Some(error),
    }
}
impl Engine {
    fn wal(&self) -> StoreResult<Wal> {
        probe(&self.db)
    }
    fn checkpoint_suppressed(&self, wal: &Wal) -> bool {
        self.backup
            .as_ref()
            .is_some_and(|c| c.suppress_checkpoint(wal.log, wal.bytes >= MAX_WAL_BYTES))
    }
    fn defer_checkpoint(&mut self) {
        // Name the debt on this receipt; the background task owns the retry.
        self.checkpoints.pending = true;
    }
    fn run_checkpoint(&mut self, wal: &Wal) -> (Option<Duration>, Option<Box<StoreError>>) {
        if self.checkpoint_suppressed(wal) {
            self.defer_checkpoint();
            return (None, None);
        }
        let start = Instant::now();
        let hard = wal.bytes >= MAX_WAL_BYTES;
        let gate = self.checkpoints.gate.clone();
        let mode = if hard { "TRUNCATE" } else { "PASSIVE" };
        let result = gate
            .acquire(self.timeout)
            .and_then(|_permit| wal_checkpoint(&self.db, mode));
        let elapsed = start.elapsed();
        let failure = classify_checkpoint(result, hard);
        self.maintenance = failure.clone();
        self.checkpoints.pending = self.maintenance.is_some();
        (Some(elapsed), failure)
    }
    pub(crate) fn require_wal_capacity(&mut self) -> StoreResult<Option<Duration>> {
        let wal = self.wal()?;
        if wal.bytes < MAX_WAL_BYTES {
            return Ok(None);
        }
        let (elapsed, failure) = self.run_checkpoint(&wal);
        // Propagate genuine storage failures (e.g., DiskFull, Corrupt,
        // Unreadable) honestly instead of collapsing them into Busy.
        if let Some(error) = failure.as_ref().filter(|e| e.code != StoreErrorCode::Busy) {
            return Err(error.clone());
        }
        // Whatever held the WAL cannot turn a failed pressure checkpoint into
        // permission to keep appending. The preceding commit stays known.
        if self.wal()?.bytes >= MAX_WAL_BYTES {
            return Err(cutoff_refusal(failure.as_deref()));
        }
        Ok(elapsed)
    }
    pub(crate) fn checkpoint_due(&mut self) -> Option<Duration> {
        let wal = match self.wal() {
            Ok(wal) => wal,
            Err(error) => {
                self.maintenance = Some(error);
                self.defer_checkpoint();
                return None;
            }
        };
        if wal.bytes >= MAX_WAL_BYTES {
            return self.run_checkpoint(&wal).0;
        }
        // Restart ahead of the cutoff, at the size the connection keeps after
        // a restart, so the next commit's trim frees only the overshoot.
        if wal.bytes >= connection::WAL_KEEP_BYTES
            && wal.log > wal.done
            && wal.log >= self.checkpoints.restart_mark + STEP_FRAMES
        {
            return self.restart(&wal);
        }
        self.request_copy(&wal);
        if wal.log >= SOFT_FRAMES && wal.log > wal.done {
            // Name the debt on this receipt. Direct/bootstrap connections have
            // no idle worker, so their close path or hard-pressure check
            // performs the maintenance; a host writer's background task owns
            // the retry.
            self.defer_checkpoint();
        } else {
            self.checkpoints.pending = false;
            if wal.log <= wal.done {
                self.maintenance = None;
            }
        }
        None
    }
    /// Restart the WAL early: copy the tail the background task left and let
    /// the next append start at frame 0. Unlike the cutoff it waits only
    /// briefly for readers, and a busy result is debt, not a failure.
    fn restart(&mut self, wal: &Wal) -> Option<Duration> {
        if self.checkpoint_suppressed(wal) {
            self.checkpoints.restart_mark = wal.log;
            self.defer_checkpoint();
            return None;
        }
        let start = Instant::now();
        let gate = self.checkpoints.gate.clone();
        let result = gate.acquire(self.timeout).and_then(|_permit| {
            self.db.busy_timeout(RESTART_WAIT).map_err(sql)?;
            let result = wal_checkpoint(&self.db, "RESTART");
            self.db.busy_timeout(self.timeout).map_err(sql)?;
            result
        });
        match result {
            Ok((0, log, done)) if log == done => {
                self.checkpoints.restart_mark = 0;
                self.checkpoints.copy_mark = 0;
                self.checkpoints.pending = false;
                self.maintenance = None;
            }
            Ok(_) => {
                self.checkpoints.restart_mark = wal.log;
                self.defer_checkpoint();
            }
            Err(error) => {
                self.checkpoints.restart_mark = wal.log;
                self.maintenance = Some(error);
                self.defer_checkpoint();
            }
        }
        Some(start.elapsed())
    }
    fn request_copy(&mut self, wal: &Wal) {
        let marks = &mut self.checkpoints;
        if wal.log < marks.copy_mark || wal.log < marks.restart_mark {
            // The WAL restarted since the marks were taken.
            marks.copy_mark = 0;
            marks.restart_mark = 0;
        }
        if wal.log - wal.done >= STEP_FRAMES && wal.log >= marks.copy_mark + STEP_FRAMES {
            marks.copy = true;
            marks.copy_mark = wal.log;
        }
    }
    /// Whether the last commit left enough uncopied frames for a background
    /// copy during traffic. Reading it consumes the request.
    pub(crate) fn take_copy_request(&mut self) -> bool {
        std::mem::take(&mut self.checkpoints.copy)
    }
    pub(crate) fn checkpoint_pending(&self) -> bool {
        self.checkpoints.pending
    }
    pub(crate) fn checkpoint_finished(&mut self, complete: bool) {
        self.checkpoints.pending = !complete;
    }
}
/// Names what held the WAL: a backup suppressed the checkpoint, the background
/// task kept the gate, or a reader pinned frames past the copy.
fn cutoff_refusal(failure: Option<&StoreError>) -> Box<StoreError> {
    let holder = match failure.map(|error| error.cause.as_str()) {
        None => "let the running or aborted backup close",
        Some(GATE_HELD) => "let background store maintenance finish its checkpoint",
        Some(_) => "release pinned readers",
    };
    let cause = format!("WAL reached its 64 MiB maintenance cutoff; {holder}, then retry");
    fail(StoreErrorCode::Busy, cause)
}
/// Protects: our own maintenance holding the gate is never blamed on readers.
#[cfg(test)]
#[test]
fn cutoff_refusal_names_own_maintenance() -> StoreResult<()> {
    let gate = Gate::default();
    let _held = gate.acquire(Duration::ZERO)?;
    let held = gate.acquire(Duration::from_millis(1)).err();
    let cause = cutoff_refusal(held.as_deref()).cause;
    assert!(cause.contains("background store maintenance"), "{cause}");
    Ok(())
}
/// Protects: equal negative frame counts are Unreadable, not the success arm.
#[cfg(test)]
#[test]
fn equal_negative_frame_counts_are_unreadable() {
    let code = |counts| classify_checkpoint(Ok(counts), false).map(|failure| failure.code);
    assert_eq!(code((0, -2, -2)), Some(StoreErrorCode::Unreadable));
    assert_eq!(code((0, 0, 0)), None);
    assert_eq!(code((1, -1, -1)), Some(StoreErrorCode::Busy));
}
