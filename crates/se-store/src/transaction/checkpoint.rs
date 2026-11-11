//! Checkpoints are writer-idle maintenance below the live WAL size cutoff.
//! COMMIT still establishes every receipt; maintenance never relabels its result.
use super::*;

const SOFT_FRAMES: i64 = 256;
const IDLE: Duration = Duration::from_millis(50);
const RETRY: Duration = Duration::from_millis(100);

#[derive(Default)]
pub(crate) struct Schedule {
    pub(crate) writer: bool,
    pending: bool,
    next: Option<Instant>,
}
struct Wal {
    log: i64,
    done: i64,
    bytes: u64,
}
impl Engine {
    fn wal(&self) -> StoreResult<Wal> {
        let (log, done) = self
            .db
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
        let page: u64 = self
            .db
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
    fn checkpoint_suppressed(&self, wal: &Wal) -> bool {
        self.backup.as_ref().is_some_and(|c| {
            c.suppress_checkpoint(wal.log, wal.bytes >= crate::backup_context::MAX_WAL_BYTES)
        })
    }
    fn defer_checkpoint(&mut self, delay: Duration) {
        self.checkpoints.pending = true;
        self.checkpoints
            .next
            .get_or_insert_with(|| Instant::now() + delay);
    }
    fn run_checkpoint(&mut self, wal: &Wal) -> Option<Duration> {
        if self.checkpoint_suppressed(wal) {
            self.defer_checkpoint(RETRY);
            return None;
        }
        let start = Instant::now();
        let hard = wal.bytes >= crate::backup_context::MAX_WAL_BYTES;
        let result = self.db.query_row(
            if hard {
                "PRAGMA wal_checkpoint(TRUNCATE)"
            } else {
                "PRAGMA wal_checkpoint(PASSIVE)"
            },
            [],
            |r| {
                Ok((
                    crate::sql_value::value::<i64>(r, 0)?,
                    crate::sql_value::value::<i64>(r, 1)?,
                    crate::sql_value::value::<i64>(r, 2)?,
                ))
            },
        );
        let elapsed = start.elapsed();
        self.maintenance = match result {
            Ok((0, log, done)) if log == done && (!hard || log == 0) => None,
            Ok(_) => Some(fail(
                StoreErrorCode::Busy,
                "committed checkpoint has pending frames",
            )),
            Err(error) => Some(sql(error)),
        };
        self.checkpoints.pending = self.maintenance.is_some();
        self.checkpoints.next = self.checkpoints.pending.then(|| Instant::now() + RETRY);
        Some(elapsed)
    }
    pub(crate) fn require_wal_capacity(&mut self) -> StoreResult<Option<Duration>> {
        let wal = self.wal()?;
        if wal.bytes < crate::backup_context::MAX_WAL_BYTES {
            return Ok(None);
        }
        let elapsed = self.run_checkpoint(&wal);
        // A pinned reader or backup cannot turn a failed pressure checkpoint
        // into permission to keep appending. The preceding commit stays known.
        if self.wal()?.bytes >= crate::backup_context::MAX_WAL_BYTES {
            return Err(fail(
                StoreErrorCode::Busy,
                "WAL reached its 64 MiB maintenance cutoff; release pinned readers or let the aborted backup close, then retry the original operation",
            ));
        }
        Ok(elapsed)
    }
    pub(super) fn checkpoint_due(&mut self) -> Option<Duration> {
        let wal = match self.wal() {
            Ok(wal) => wal,
            Err(error) => {
                self.maintenance = Some(error);
                self.defer_checkpoint(RETRY);
                return None;
            }
        };
        if wal.bytes >= crate::backup_context::MAX_WAL_BYTES {
            return self.run_checkpoint(&wal);
        }
        if wal.log >= SOFT_FRAMES && wal.log > wal.done {
            if self.checkpoints.writer {
                self.defer_checkpoint(IDLE);
                None
            } else {
                self.run_checkpoint(&wal)
            }
        } else {
            self.checkpoints.pending = false;
            self.checkpoints.next = None;
            if wal.log <= wal.done {
                self.maintenance = None;
            }
            None
        }
    }
    pub(crate) fn checkpoint_wait(&self) -> Option<Duration> {
        if self.poisoned || !self.checkpoints.pending {
            return None;
        }
        self.checkpoints
            .next
            .map(|at| at.saturating_duration_since(Instant::now()))
    }
    pub(crate) fn checkpoint_idle(&mut self) {
        self.checkpoints.next = None;
        match self.wal() {
            Ok(wal) => {
                self.run_checkpoint(&wal);
            }
            Err(error) => {
                self.maintenance = Some(error);
                self.defer_checkpoint(RETRY);
            }
        }
    }
    pub(crate) fn checkpoint_pending(&self) -> bool {
        self.checkpoints.pending
    }
    pub(crate) fn checkpoint_finished(&mut self, complete: bool) {
        self.checkpoints.pending = !complete;
        self.checkpoints.next = (!complete).then(|| Instant::now() + RETRY);
    }
}
