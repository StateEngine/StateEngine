//! One writer/reader globally, finite transactions and a separately qualified SQL share.
use super::*;
use crate::errors::{cache_error, capacity};
use rusqlite::{Connection, OpenFlags, Statement, StatementStatus, limits::Limit};
use std::{
    cell::Cell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};
static SLOTS: AtomicU8 = AtomicU8::new(0);
const READER_SLOT: u8 = 1;
const WRITER_SLOT: u8 = 2;
const QUERY_ARENA_SLOT: u8 = 4;
const PAGE_BYTES: u64 = 4096;
const WAL_STOP: u64 = 8_000_000;
const STATEMENT_BYTES: usize = 16_384;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionRole {
    HostReader,
    HostWriter,
    ExternalReader,
    ColdWriter,
}
impl ConnectionRole {
    fn writable(self) -> bool {
        matches!(self, Self::HostWriter | Self::ColdWriter)
    }
}
/// Measured upper bound from native SQL/allocator qualification, not an estimate
/// or a request-supplied flag. Until that witness exists the host must not admit
/// the profile. Two page caches, statement allowances and one query arena reserve
/// 393216 bytes; connection/SQLite overhead must fit the remaining 106784.
pub struct SqlProfile {
    overhead: u32,
}
impl SqlProfile {
    pub fn from_qualified_overhead(bytes: u32) -> AtlasResult<Self> {
        if bytes == 0 || bytes > 53_392 {
            return Err(capacity(
                "Atlas SQL connection overhead",
                u64::from(bytes),
                53_392,
            ));
        }
        Ok(Self { overhead: bytes })
    }
}
struct Slot(u8);
impl Slot {
    fn take(role: ConnectionRole) -> AtlasResult<Self> {
        let bit = match role {
            ConnectionRole::HostReader => READER_SLOT,
            ConnectionRole::HostWriter => WRITER_SLOT,
            _ => 0,
        };
        if bit != 0 && SLOTS.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
            return Err(capacity("Atlas global SQL reader/writer slot", 1, 0));
        }
        Ok(Self(bit))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        SLOTS.fetch_and(!self.0, Ordering::Release);
    }
}
pub struct CacheConnection<'a> {
    db: Connection,
    files: &'a dyn CacheFiles,
    pin: DatabasePin,
    identity: CacheIdentity,
    role: ConnectionRole,
    _slot: Slot,
}
impl<'a> CacheConnection<'a> {
    pub fn open(
        files: &'a dyn CacheFiles,
        id: CacheIdentity,
        role: ConnectionRole,
        profile: &SqlProfile,
        deadline: Instant,
    ) -> AtlasResult<Option<Self>> {
        let Some(pin) = files.pin_database(&id.epoch)? else {
            return Ok(None);
        };
        let slot = Slot::take(role)?;
        files.validate_database(&pin)?;
        let db = open(&pin, role, deadline)?;
        finite(&db, deadline, |_| {
            schema::validate(&db, &id)?;
            if role.writable() {
                schema::validate_integrity(&db)?;
            }
            Ok(())
        })?;
        configure(&db, role, profile)?;
        files.validate_database(&pin)?;
        Ok(Some(Self {
            db,
            files,
            pin,
            identity: id,
            role,
            _slot: slot,
        }))
    }
    /// Only an exclusive runtime/cache writer may reserve a fresh epoch. No
    /// open-existing path creates or migrates a database as a side effect.
    pub fn create(
        files: &'a dyn CacheFiles,
        seed: &CacheSeed,
        role: ConnectionRole,
        profile: &SqlProfile,
        deadline: Instant,
    ) -> AtlasResult<Self> {
        if !role.writable() {
            return Err(cache_error("readers cannot create epochs"));
        }
        let slot = Slot::take(role)?;
        let _growth = files.reserve_growth(1_000_000)?;
        let pin = files.reserve_database(&seed.identity.epoch)?;
        let initialized = (|| {
            files.validate_database(&pin)?;
            if pin.file.metadata().map_err(cache_error)?.len() != 0 {
                return Err(cache_error("new epoch reservation is not empty"));
            }
            let db = open(&pin, role, deadline)?;
            db.execute_batch("PRAGMA page_size=4096")
                .map_err(cache_error)?;
            configure(&db, role, profile)?;
            finite(&db, deadline, |_| {
                db.execute_batch("BEGIN EXCLUSIVE").map_err(cache_error)?;
                let result = schema::initialize(&db, seed);
                if let Err(original) = result {
                    return match db.execute_batch("ROLLBACK") {
                        Ok(()) => Err(original),
                        Err(rollback) => Err(original.with_cause(rollback)),
                    };
                }
                db.execute_batch("COMMIT").map_err(cache_error)?;
                schema::validate(&db, &seed.identity)?;
                schema::validate_integrity(&db)
            })?;
            db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(cache_error)?;
            files.validate_database(&pin)?;
            Ok(db)
        })();
        let db = match initialized {
            Ok(db) => db,
            Err(original) => {
                return match files.discard_unpublished(&pin) {
                    Ok(()) => Err(original),
                    Err(cleanup) => Err(original.with_cause(cleanup)),
                };
            }
        };
        Ok(Self {
            db,
            files,
            pin,
            identity: seed.identity.clone(),
            role,
            _slot: slot,
        })
    }
    pub fn validate(&self, deadline: Instant) -> AtlasResult<()> {
        self.files.validate_database(&self.pin)?;
        finite(&self.db, deadline, |_| {
            schema::validate(&self.db, &self.identity)
        })
    }
    pub fn identity(&self) -> &CacheIdentity {
        &self.identity
    }
    /// A finite snapshot ends at response completion, including error paths.
    /// Output allocations belong to the host's single 98304-byte query arena.
    pub fn read<T>(
        &self,
        deadline: Instant,
        read: impl FnOnce(&SqlView<'_>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        self.transaction(false, 0, deadline, read)
    }
    /// The bounded update owner supplies its maximum WAL emission before SQL
    /// runs; native reservation holds DB/WAL/retired/staging/global disk capacity.
    /// Underestimating emission is an invariant violation, never a renewed budget.
    pub fn write<T>(
        &self,
        maximum_wal_bytes: u64,
        deadline: Instant,
        write: impl FnOnce(&SqlView<'_>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        if !self.role.writable() {
            return Err(cache_error("read-only Atlas connection"));
        }
        self.transaction(true, maximum_wal_bytes, deadline, write)
    }
    fn transaction<T>(
        &self,
        write: bool,
        growth: u64,
        deadline: Instant,
        work: impl FnOnce(&SqlView<'_>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        let _arena = if matches!(
            self.role,
            ConnectionRole::HostReader | ConnectionRole::HostWriter
        ) {
            if SLOTS.fetch_or(QUERY_ARENA_SLOT, Ordering::AcqRel) & QUERY_ARENA_SLOT != 0 {
                return Err(capacity("Atlas shared SQL/query arena", 1, 0));
            }
            Some(Slot(QUERY_ARENA_SLOT))
        } else {
            None
        };
        self.files.validate_database(&self.pin)?;
        let wal = self.files.wal_bytes(&self.pin)?;
        if write && (growth > WAL_STOP || wal.checked_add(growth).is_none_or(|v| v > WAL_STOP)) {
            return Err(capacity(
                "Atlas WAL capacity; checkpoint or release external readers",
                growth,
                WAL_STOP.saturating_sub(wal),
            ));
        }
        let _reservation = if write {
            Some(self.files.reserve_growth(growth)?)
        } else {
            None
        };
        finite(&self.db, deadline, |budget_ms| {
            let behavior = if write {
                rusqlite::TransactionBehavior::Immediate
            } else {
                rusqlite::TransactionBehavior::Deferred
            };
            let transaction =
                rusqlite::Transaction::new_unchecked(&self.db, behavior).map_err(cache_error)?;
            let result = work(&SqlView {
                db: &self.db,
                count: Cell::new(0),
                bytes: Cell::new(0),
                readonly: !write,
            });
            let changed = self.files.validate_database(&self.pin);
            let expired = Instant::now() >= deadline;
            let result = match (result, changed, expired) {
                (_, _, true) => Err(timeout(budget_ms)),
                (Ok(value), Ok(()), false) => Ok(value),
                (Err(e), _, false) | (_, Err(e), false) => Err(e),
            };
            if result.is_ok() && write {
                transaction.commit().map_err(cache_error)?;
            } else {
                transaction.rollback().map_err(cache_error)?;
            }
            result
        })
    }
    /// Event/commit/drain driven only. External pinned snapshots keep writes
    /// suspended; no timer or forced reader expiry is introduced.
    pub fn checkpoint(&self, deadline: Instant) -> AtlasResult<bool> {
        if !self.role.writable() {
            return Err(cache_error("reader cannot checkpoint"));
        }
        let wal = self.files.wal_bytes(&self.pin)?;
        if wal < 4_000_000 {
            return Ok(true);
        }
        finite(&self.db, deadline, |_| {
            let (busy, _, _): (i64, i64, i64) = self
                .db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(cache_error)?;
            Ok(busy == 0)
        })
    }
}
fn open(pin: &DatabasePin, role: ConnectionRole, deadline: Instant) -> AtlasResult<Connection> {
    if Instant::now() >= deadline {
        return Err(timeout(0));
    }
    let flags = if role.writable() {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let db = Connection::open_with_flags(
        &pin.path,
        flags
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_EXRESCODE,
    )
    .map_err(cache_error)?;
    db.busy_timeout(
        deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(25)),
    )
    .map_err(cache_error)?;
    Ok(db)
}
fn configure(db: &Connection, role: ConnectionRole, profile: &SqlProfile) -> AtlasResult<()> {
    let _qualified_overhead = profile.overhead;
    db.set_prepared_statement_cache_capacity(0);
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, 131072),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 16384),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        db.set_limit(limit, value).map_err(cache_error)?;
    }
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA cache_size=32;").map_err(cache_error)?;
    if role == ConnectionRole::ColdWriter {
        db.execute_batch("PRAGMA cache_size=488")
            .map_err(cache_error)?;
    }
    if role.writable() {
        let journal: String = db
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(cache_error)?;
        if journal != "wal" {
            return Err(cache_error("WAL mode refused"));
        }
        db.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=4000000; PRAGMA max_page_count=125000;").map_err(cache_error)?;
    } else {
        db.execute_batch("PRAGMA query_only=ON")
            .map_err(cache_error)?;
    }
    for (pragma, want) in [
        ("page_size", PAGE_BYTES as i64),
        ("foreign_keys", 1),
        ("temp_store", 1),
        ("mmap_size", 0),
    ] {
        let actual: i64 = db
            .pragma_query_value(None, pragma, |r| r.get(0))
            .map_err(cache_error)?;
        if actual != want {
            return Err(cache_error(format!("{pragma} readback differs")));
        }
    }
    Ok(())
}
fn finite<T>(
    db: &Connection,
    deadline: Instant,
    work: impl FnOnce(u64) -> AtlasResult<T>,
) -> AtlasResult<T> {
    if Instant::now() >= deadline {
        return Err(timeout(0));
    }
    let budget_ms = u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    db.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(cache_error)?;
    let result = work(budget_ms);
    db.progress_handler(0, None::<fn() -> bool>)
        .map_err(cache_error)?;
    if Instant::now() >= deadline {
        Err(timeout(budget_ms))
    } else {
        result
    }
}
fn timeout(budget_ms: u64) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::DeadlineExceeded(
        se_types::details::DeadlineExceeded {
            op: "Atlas SQL".into(),
            deadline_ms: budget_ms,
        },
    ))
}
pub struct SqlView<'a> {
    db: &'a Connection,
    count: Cell<usize>,
    bytes: Cell<usize>,
    readonly: bool,
}
impl SqlView<'_> {
    pub fn prepare(&self, sql: &str) -> AtlasResult<BudgetStatement<'_>> {
        let stmt = self.db.prepare(sql).map_err(cache_error)?;
        if self.readonly && !stmt.readonly() {
            return Err(cache_error(
                "mutation attempted inside an Atlas read snapshot",
            ));
        }
        let bytes =
            usize::try_from(stmt.get_status(StatementStatus::MemUsed)).map_err(cache_error)?;
        if self.count.get() >= 8 || self.bytes.get() + bytes > STATEMENT_BYTES {
            return Err(capacity(
                "Atlas SQL statement memory",
                bytes as u64,
                STATEMENT_BYTES.saturating_sub(self.bytes.get()) as u64,
            ));
        }
        self.count.set(self.count.get() + 1);
        self.bytes.set(self.bytes.get() + bytes);
        Ok(BudgetStatement {
            stmt,
            count: &self.count,
            bytes: &self.bytes,
            reserved: bytes,
        })
    }
}
pub struct BudgetStatement<'a> {
    stmt: Statement<'a>,
    count: &'a Cell<usize>,
    bytes: &'a Cell<usize>,
    reserved: usize,
}
impl<'a> Deref for BudgetStatement<'a> {
    type Target = Statement<'a>;
    fn deref(&self) -> &Self::Target {
        &self.stmt
    }
}
impl DerefMut for BudgetStatement<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stmt
    }
}
impl Drop for BudgetStatement<'_> {
    fn drop(&mut self) {
        self.count.set(self.count.get() - 1);
        self.bytes.set(self.bytes.get() - self.reserved);
    }
}

#[cfg(test)]
#[path = "statement_tests.rs"]
mod statement_tests;
