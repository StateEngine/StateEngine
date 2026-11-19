//! Bounded unpublished cold-index transactions, with per-operation rollback.
use super::*;

const FILE_ALLOWANCE: u64 = 2_065_536;
const BATCH_ALLOWANCE: u64 = FILE_ALLOWANCE * 3;
const BATCH_FILES: u8 = 3;
const BATCH_TIME: Duration = Duration::from_secs(2);

pub(super) struct Batch<'a> {
    _reservation: Box<dyn GrowthReservation + 'a>,
    started: Instant,
    growth: u64,
    files: u8,
    poisoned: bool,
}

impl<'a> CacheConnection<'a> {
    /// Start a file within an unpublished cold batch. Bounds apply at file
    /// boundaries; the existing source and SQL deadlines bound the current file.
    pub fn prepare_cold_file(&mut self, deadline: Instant) -> AtlasResult<()> {
        if self.role != ConnectionRole::ColdWriter {
            return Err(cache_error("cold batch requires the contained writer"));
        }
        if self.cold_batch_needs_flush() {
            return Err(cache_error(
                "cold batch must be finished before another file",
            ));
        }
        if self.cold_batch.is_none() {
            self.files.validate_database(&self.pin)?;
            let mut wal = self.files.wal_bytes(&self.pin)?;
            if wal.saturating_add(BATCH_ALLOWANCE) > WAL_STOP {
                let busy: i64 = finite(&mut self.db, deadline, |db, _| {
                    db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
                        .map_err(cache_error)
                })?;
                if busy != 0 {
                    return Err(cache_error(
                        "unpublished cold epoch checkpoint remains busy",
                    ));
                }
                wal = self.files.wal_bytes(&self.pin)?;
            }
            if wal.saturating_add(BATCH_ALLOWANCE) > WAL_STOP {
                return Err(capacity(
                    "Atlas WAL capacity for cold batch",
                    BATCH_ALLOWANCE,
                    WAL_STOP.saturating_sub(wal),
                ));
            }
            let files: &'a dyn CacheFiles = self.files;
            let reservation = files.reserve_growth(BATCH_ALLOWANCE)?;
            finite(&mut self.db, deadline, |db, _| {
                db.execute_batch("BEGIN IMMEDIATE").map_err(cache_error)
            })?;
            self.cold_batch = Some(Batch {
                _reservation: reservation,
                started: Instant::now(),
                growth: 0,
                files: 0,
                poisoned: false,
            });
        }
        if let Some(batch) = &mut self.cold_batch {
            batch.files += 1;
        }
        Ok(())
    }

    pub fn cold_batch_needs_flush(&self) -> bool {
        self.cold_batch.as_ref().is_some_and(|batch| {
            batch.files >= BATCH_FILES
                || batch.started.elapsed() >= BATCH_TIME
                || batch.growth.saturating_add(FILE_ALLOWANCE) > BATCH_ALLOWANCE
        })
    }

    /// Publish only to the private epoch. Failure leaves the candidate
    /// unpublished and SQLite rolls back any still-open transaction on close.
    pub fn finish_cold_batch(&mut self, deadline: Instant) -> AtlasResult<()> {
        if self.cold_batch.is_none() {
            return Ok(());
        }
        if self.cold_batch.as_ref().is_some_and(|batch| batch.poisoned) {
            return Err(cache_error(
                "cold batch requires rollback after an incomplete operation",
            ));
        }
        self.files.validate_database(&self.pin)?;
        finite(&mut self.db, deadline, |db, _| {
            db.execute_batch("COMMIT").map_err(cache_error)
        })?;
        self.cold_batch.take();
        if !self.checkpoint(deadline)? {
            return Err(cache_error(
                "unpublished cold epoch checkpoint remains busy",
            ));
        }
        Ok(())
    }

    pub(super) fn cold_batch_transaction<T>(
        &mut self,
        write: bool,
        growth: u64,
        deadline: Instant,
        work: impl FnOnce(&SqlView<'_>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        let batch = self
            .cold_batch
            .as_mut()
            .ok_or_else(|| cache_error("cold batch absent"))?;
        if batch.poisoned {
            return Err(cache_error(
                "cold batch requires rollback after an incomplete operation",
            ));
        }
        if write {
            batch.growth = batch
                .growth
                .checked_add(growth)
                .ok_or_else(|| cache_error("cold batch growth overflow"))?;
            if batch.growth > BATCH_ALLOWANCE {
                return Err(capacity("Atlas cold batch growth", growth, BATCH_ALLOWANCE));
            }
        }
        self.files.validate_database(&self.pin)?;
        let finished = Cell::new(false);
        let retained_write = Cell::new(false);
        let result = finite(&mut self.db, deadline, |db, budget_ms| {
            db.execute_batch("SAVEPOINT atlas_cold_file")
                .map_err(cache_error)?;
            let result = work(&SqlView {
                db,
                count: Cell::new(0),
                bytes: Cell::new(0),
                readonly: !write,
                deadline,
            });
            let changed = self.files.validate_database(&self.pin);
            let result = match (result, changed, crate::clock::now() >= deadline) {
                (_, _, true) => Err(timeout(budget_ms)),
                (Ok(value), Ok(()), false) => Ok(value),
                (Err(error), _, false) | (_, Err(error), false) => Err(error),
            };
            if result.is_err() || !write {
                db.execute_batch("ROLLBACK TO atlas_cold_file")
                    .map_err(cache_error)?;
            }
            db.execute_batch("RELEASE atlas_cold_file")
                .map_err(cache_error)?;
            retained_write.set(write && result.is_ok());
            finished.set(true);
            result
        });
        if (!finished.get() || retained_write.get() && result.is_err())
            && let Some(batch) = &mut self.cold_batch
        {
            batch.poisoned = true;
        }
        result
    }
}
