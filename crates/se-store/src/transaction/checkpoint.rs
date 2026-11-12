//! WAL maintenance state shared by the commit path and the background task.
//! COMMIT still establishes every receipt; maintenance never relabels its result.
use super::*;

const SOFT_FRAMES: i64 = 256;

#[derive(Default)]
pub(crate) struct Schedule {
    pending: bool,
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
impl Engine {
    fn wal(&self) -> StoreResult<Wal> {
        probe(&self.db)
    }
    fn checkpoint_suppressed(&self, wal: &Wal) -> bool {
        self.backup.as_ref().is_some_and(|c| {
            c.suppress_checkpoint(wal.log, wal.bytes >= crate::backup_context::MAX_WAL_BYTES)
        })
    }
    fn defer_checkpoint(&mut self) {
        // Name the debt on this receipt; the background task owns the retry.
        self.checkpoints.pending = true;
    }
    fn run_checkpoint(&mut self, wal: &Wal) -> Option<Duration> {
        if self.checkpoint_suppressed(wal) {
            self.defer_checkpoint();
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
    pub(crate) fn checkpoint_due(&mut self) -> Option<Duration> {
        let wal = match self.wal() {
            Ok(wal) => wal,
            Err(error) => {
                self.maintenance = Some(error);
                self.defer_checkpoint();
                return None;
            }
        };
        if wal.bytes >= crate::backup_context::MAX_WAL_BYTES {
            return self.run_checkpoint(&wal);
        }
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
    pub(crate) fn checkpoint_pending(&self) -> bool {
        self.checkpoints.pending
    }
    pub(crate) fn checkpoint_finished(&mut self, complete: bool) {
        self.checkpoints.pending = !complete;
    }
}
