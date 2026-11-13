//! One writer/reader globally, finite transactions and a separately qualified SQL share.
use super::*;
use crate::errors::{cache_error, capacity};
use rusqlite::{Connection, OpenFlags, Statement, StatementStatus, limits::Limit};
use std::{
    cell::Cell,
    ops::Deref,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
#[path = "query_arena.rs"]
mod query_arena;
#[path = "statement.rs"]
mod statement;
pub use statement::{BudgetStatement, SqlView};
pub type NativeSqlConnection = rusqlite::Connection;
static SLOTS: AtomicU8 = AtomicU8::new(0);
static READER_WAIT: Mutex<()> = Mutex::new(());
static READER_READY: Condvar = Condvar::new();
const READER_SLOT: u8 = 1;
const WRITER_SLOT: u8 = 2;
const PAGE_BYTES: u64 = 4096;
const WAL_STOP: u64 = 8_000_000;
const STATEMENT_BYTES: usize = 16_384;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionRole {
    HostReader,
    /// A synchronous foreground query queues before opening SQLite and before
    /// creating its short execution deadline. It owns the shared result arena
    /// through connection close, including WAL startup and teardown.
    QueryReader,
    HostWriter,
    /// The native owner already integrity-checked this exact epoch at activation
    /// or post-reap adoption. Scope, schema and native identity still validate
    /// on every open; a maintenance quantum never repeats the whole-page scan.
    MaintenanceWriter,
    ExternalReader,
    /// Explicit read-only integrity validation shares the foreground reader
    /// slot, for example when close discovers an unrecognized epoch.
    CandidateReader,
    /// Post-reap ownership of an unpublished epoch consumes the maintenance
    /// writer allowance. Its whole-graph check leaves the foreground reader
    /// available for the previously published epoch; no third handle is added.
    CandidateWriter,
    ColdWriter,
}
impl ConnectionRole {
    fn writable(self) -> bool {
        matches!(
            self,
            Self::HostWriter | Self::MaintenanceWriter | Self::CandidateWriter | Self::ColdWriter
        )
    }
}
/// Measured upper bound from native SQL/allocator qualification, not an estimate
/// or a request-supplied flag. Until that witness exists the host must not admit
/// the profile. Two page caches, statement allowances and one query arena reserve
/// 262144 bytes; measured connection/SQLite overhead shares the 600 KB SQL
/// reservation. The extra 100 KB comes from the coalesced queue, not the total.
#[derive(Clone, Debug)]
pub struct SqlProfile {
    overhead: u32,
    cold_only: bool,
}
impl SqlProfile {
    pub fn from_qualified_overhead(bytes: u32) -> AtlasResult<Self> {
        let maximum = (crate::model::SQL_QUERY_BYTES - 262_144) / 2;
        if bytes == 0 || bytes > maximum {
            return Err(capacity(
                "Atlas SQL connection overhead",
                u64::from(bytes),
                u64::from(maximum),
            ));
        }
        Ok(Self {
            overhead: bytes,
            cold_only: false,
        })
    }
    pub fn qualified_overhead_bytes(&self) -> Option<u32> {
        (!self.cold_only).then_some(self.overhead)
    }
    /// Cold-window reservation, not evidence of the host's 600 KB SQL share.
    /// External validation may use it only outside the steady host read path.
    pub fn contained_cold() -> Self {
        Self {
            overhead: 0,
            cold_only: true,
        }
    }
}
struct Slot(u8);
impl Slot {
    fn take(role: ConnectionRole, deadline: Instant) -> AtlasResult<Self> {
        let bit = match role {
            ConnectionRole::HostReader
            | ConnectionRole::QueryReader
            | ConnectionRole::CandidateReader => READER_SLOT,
            ConnectionRole::HostWriter
            | ConnectionRole::MaintenanceWriter
            | ConnectionRole::CandidateWriter => WRITER_SLOT,
            _ => 0,
        };
        if bit == READER_SLOT {
            let mut guard = READER_WAIT
                .lock()
                .map_err(|_| cache_error("Atlas reader slot lock poisoned"))?;
            while SLOTS.load(Ordering::Acquire) & bit != 0 {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(timeout(0));
                }
                guard = READER_READY
                    .wait_timeout(guard, remaining)
                    .map_err(|_| cache_error("Atlas reader slot wait poisoned"))?
                    .0;
            }
            SLOTS.fetch_or(bit, Ordering::AcqRel);
            return Ok(Self(bit));
        }
        if bit != 0 && SLOTS.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
            return Err(capacity("Atlas global SQL reader/writer slot", 1, 0));
        }
        Ok(Self(bit))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        let _guard = (self.0 == READER_SLOT).then(|| {
            READER_WAIT
                .lock()
                .unwrap_or_else(|error| error.into_inner())
        });
        SLOTS.fetch_and(!self.0, Ordering::Release);
        if self.0 == READER_SLOT {
            READER_READY.notify_all();
        }
    }
}
pub struct CacheConnection<'a> {
    db: Connection,
    files: &'a dyn CacheFiles,
    pin: DatabasePin,
    identity: CacheIdentity,
    role: ConnectionRole,
    arena: Option<query_arena::Reservation>,
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
        let slot = Slot::take(role, deadline)?;
        // The native work/query adapters close their handles before returning.
        // Include open and close in the same arena: WAL startup/checkpoint locks
        // can otherwise race even when SQL transactions are serialized.
        let arena = if matches!(
            role,
            ConnectionRole::QueryReader | ConnectionRole::MaintenanceWriter
        ) {
            Some(query_arena::Reservation::acquire(
                role == ConnectionRole::QueryReader,
                deadline,
            )?)
        } else {
            None
        };
        files.validate_database(&pin)?;
        let mut db = open(&pin, role, deadline)?;
        files.configure_connection_role(&mut db, role)?;
        configure_limits(&db, role, profile)?;
        finite(&mut db, deadline, |db, _| {
            schema::validate(db, &id)?;
            if role.writable() && role != ConnectionRole::MaintenanceWriter {
                schema::validate_integrity(db)?;
            }
            Ok(())
        })?;
        configure_access(&db, role)?;
        if role == ConnectionRole::CandidateReader {
            finite(&mut db, deadline, |db, _| schema::validate_integrity(db))?;
        }
        files.validate_database(&pin)?;
        Ok(Some(Self {
            db,
            files,
            pin,
            identity: id,
            role,
            arena,
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
        let slot = Slot::take(role, deadline)?;
        let _growth = files.reserve_growth(1_000_000)?;
        let pin = files.reserve_database(&seed.identity.epoch)?;
        let initialized = (|| {
            files.validate_database(&pin)?;
            if pin.file.metadata().map_err(cache_error)?.len() != 0 {
                return Err(cache_error("new epoch reservation is not empty"));
            }
            let mut db = open(&pin, role, deadline)?;
            files.configure_connection_role(&mut db, role)?;
            db.execute_batch("PRAGMA page_size=4096")
                .map_err(cache_error)?;
            configure(&db, role, profile)?;
            finite(&mut db, deadline, |db, _| {
                db.execute_batch("BEGIN EXCLUSIVE").map_err(cache_error)?;
                let result = schema::initialize(db, seed);
                if let Err(original) = result {
                    return match db.execute_batch("ROLLBACK") {
                        Ok(()) => Err(original),
                        Err(rollback) => Err(original.with_cause(rollback)),
                    };
                }
                db.execute_batch("COMMIT").map_err(cache_error)?;
                schema::validate(db, &seed.identity)?;
                schema::validate_integrity(db)
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
            arena: None,
            _slot: slot,
        })
    }
    pub fn validate(&mut self, deadline: Instant) -> AtlasResult<()> {
        self.files.validate_database(&self.pin)?;
        finite(&mut self.db, deadline, |db, _| {
            schema::validate(db, &self.identity)
        })
    }
    pub fn identity(&self) -> &CacheIdentity {
        &self.identity
    }
    /// A finite snapshot ends at response completion, including error paths.
    /// Output allocations belong to the host's single 98304-byte query arena.
    pub fn read<T>(
        &mut self,
        deadline: Instant,
        read: impl FnOnce(&SqlView<'_>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        self.transaction(false, 0, deadline, read)
    }
    /// The bounded update owner supplies its maximum WAL emission before SQL
    /// runs; native reservation holds DB/WAL/retired/staging/global disk capacity.
    /// Underestimating emission is an invariant violation, never a renewed budget.
    pub fn write<T>(
        &mut self,
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
        &mut self,
        write: bool,
        growth: u64,
        deadline: Instant,
        work: impl FnOnce(&SqlView<'_>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        let _arena = if self.arena.is_none()
            && matches!(
                self.role,
                ConnectionRole::HostReader
                    | ConnectionRole::QueryReader
                    | ConnectionRole::HostWriter
                    | ConnectionRole::MaintenanceWriter
            ) {
            Some(query_arena::Reservation::acquire(
                matches!(
                    self.role,
                    ConnectionRole::HostReader | ConnectionRole::QueryReader
                ),
                deadline,
            )?)
        } else {
            None
        };
        self.files.validate_database(&self.pin)?;
        if write {
            let wal = self.files.wal_bytes(&self.pin)?;
            if growth > WAL_STOP || wal.checked_add(growth).is_none_or(|v| v > WAL_STOP) {
                return Err(capacity(
                    "Atlas WAL capacity; checkpoint or release external readers",
                    growth,
                    WAL_STOP.saturating_sub(wal),
                ));
            }
        }
        let _reservation = if write {
            Some(self.files.reserve_growth(growth)?)
        } else {
            None
        };
        finite(&mut self.db, deadline, |db, budget_ms| {
            let behavior = if write {
                rusqlite::TransactionBehavior::Immediate
            } else {
                rusqlite::TransactionBehavior::Deferred
            };
            let transaction =
                rusqlite::Transaction::new_unchecked(db, behavior).map_err(cache_error)?;
            let result = work(&SqlView {
                db,
                count: Cell::new(0),
                bytes: Cell::new(0),
                readonly: !write,
                deadline,
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
    pub fn checkpoint(&mut self, deadline: Instant) -> AtlasResult<bool> {
        if !self.role.writable() {
            return Err(cache_error("reader cannot checkpoint"));
        }
        let wal = self.files.wal_bytes(&self.pin)?;
        if wal < 4_000_000 {
            return Ok(true);
        }
        finite(&mut self.db, deadline, |db, _| {
            let (busy, _, _): (i64, i64, i64) = db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(cache_error)?;
            Ok(busy == 0)
        })
    }
    /// Release reusable page buffers between cold files so the native parser
    /// margin does not become permanently occupied by the previous SQL work.
    /// No transaction or statement may cross this synchronous boundary.
    pub fn release_cold_memory(&mut self, deadline: Instant) -> AtlasResult<()> {
        if self.role != ConnectionRole::ColdWriter {
            return Err(cache_error(
                "cold memory release requires the contained writer",
            ));
        }
        self.files.validate_database(&self.pin)?;
        finite(&mut self.db, deadline, |db, _| {
            db.release_memory().map_err(cache_error)
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
    // SQLite appends `-wal`/`-shm` to this name and opens them through its own
    // Win32 calls, so an ordinary path would be capped at MAX_PATH. The
    // verbatim form lets the sidecars exist at any reachable length; the file
    // opened is the one the pin names.
    let target = se_types::sqlite_path(&pin.path);
    // SQLite's NOFOLLOW refuses a verbatim path it cannot resolve with its own
    // walk; the retained pin already names the exact file, so the flag is
    // dropped only for the verbatim form.
    let symlink_guard = if target == pin.path {
        OpenFlags::SQLITE_OPEN_NOFOLLOW
    } else {
        OpenFlags::empty()
    };
    let mut db = Connection::open_with_flags(
        &target,
        flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_EXRESCODE | symlink_guard,
    )
    .map_err(cache_error)?;
    db.busy_timeout(
        deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(25)),
    )
    .map_err(cache_error)?;
    if role == ConnectionRole::ColdWriter {
        // This epoch is unpublished and has exactly one contained writer.
        // Exclusive WAL uses an in-process index, never a mapped -shm file.
        // Host handles retain normal locking after exact child reap/close.
        finite(&mut db, deadline, |db, _| {
            let locking: String = db
                .query_row("PRAGMA locking_mode=EXCLUSIVE", [], |r| r.get(0))
                .map_err(cache_error)?;
            if locking != "exclusive" {
                return Err(cache_error("cold exclusive WAL locking refused"));
            }
            Ok(())
        })?;
    }
    Ok(db)
}
fn configure(db: &Connection, role: ConnectionRole, profile: &SqlProfile) -> AtlasResult<()> {
    configure_limits(db, role, profile)?;
    configure_access(db, role)
}
fn configure_limits(
    db: &Connection,
    role: ConnectionRole,
    profile: &SqlProfile,
) -> AtlasResult<()> {
    if profile.cold_only
        && matches!(
            role,
            ConnectionRole::HostReader
                | ConnectionRole::QueryReader
                | ConnectionRole::HostWriter
                | ConnectionRole::MaintenanceWriter
        )
    {
        return Err(cache_error(
            "cold SQL reservations cannot admit steady host connections",
        ));
    }
    let _qualified_overhead = profile.overhead;
    super::path_scope::register(db)?;
    db.set_prepared_statement_cache_capacity(0);
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, 131072),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 16384),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        db.set_limit(limit, value).map_err(cache_error)?;
    }
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA cache_size=16;").map_err(cache_error)?;
    if role == ConnectionRole::ColdWriter {
        db.execute_batch("PRAGMA cache_size=488")
            .map_err(cache_error)?;
    }
    Ok(())
}
fn configure_access(db: &Connection, role: ConnectionRole) -> AtlasResult<()> {
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
    db: &mut Connection,
    deadline: Instant,
    work: impl FnOnce(&Connection, u64) -> AtlasResult<T>,
) -> AtlasResult<T> {
    if Instant::now() >= deadline {
        return Err(timeout(0));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(timeout(0));
    }
    let budget_ms = u64::try_from(remaining.as_millis())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(
            !remaining.subsec_nanos().is_multiple_of(1_000_000),
        ));
    db.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(cache_error)?;
    let result = work(db, budget_ms);
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

#[cfg(test)]
#[path = "statement_tests.rs"]
mod statement_tests;
