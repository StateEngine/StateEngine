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
use query_arena::Reservation;
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
    /// creating its short execution deadline. It opens and closes inside the
    /// shared arena; its queries read their own WAL snapshot outside it.
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
    /// Opens and closes inside the arena, and works outside it in between.
    fn opens_in_arena(self) -> bool {
        matches!(self, Self::QueryReader | Self::MaintenanceWriter)
    }
}
/// Native SQL/allocator qualification, not an estimate or request-supplied flag.
/// A profile may carry measured per-connection overhead or a measured combined
/// two-connection peak. The latter does not imply a per-connection measurement.
#[derive(Clone, Debug)]
pub struct SqlProfile {
    overhead: Option<u32>,
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
            overhead: Some(bytes),
            cold_only: false,
        })
    }
    /// A measured two-connection peak qualifies their shared reservation, but
    /// does not establish a separate per-connection overhead measurement.
    pub fn from_qualified_joined(bytes: u32) -> AtlasResult<Self> {
        if bytes == 0 || bytes > crate::model::SQL_QUERY_BYTES {
            return Err(capacity(
                "Atlas joined SQL commit",
                u64::from(bytes),
                u64::from(crate::model::SQL_QUERY_BYTES),
            ));
        }
        Ok(Self {
            overhead: None,
            cold_only: false,
        })
    }
    pub fn qualified_overhead_bytes(&self) -> Option<u32> {
        self.overhead
    }
    /// Cold-window reservation, not evidence of the host's 600 KB SQL share.
    /// External validation may use it only outside the steady host read path.
    pub fn contained_cold() -> Self {
        Self {
            overhead: None,
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
            let started = Instant::now();
            let deadline = crate::clock::wait_deadline(deadline);
            let budget = deadline.saturating_duration_since(started);
            let mut guard = READER_WAIT
                .lock()
                .map_err(|_| cache_error("Atlas reader slot lock poisoned"))?;
            while SLOTS.load(Ordering::Acquire) & bit != 0 {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(if role != ConnectionRole::QueryReader || budget.is_zero() {
                        stage_timeout("reader slot admission", 0)
                    } else {
                        timeout_phase("reader slot admission", budget, started.elapsed())
                    });
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
    arena: Option<Reservation>,
    _slot: Slot,
    until: Instant, // The latest caller budget; closing waits for the arena no longer.
}
impl Drop for CacheConnection<'_> {
    fn drop(&mut self) {
        if self.role == ConnectionRole::ColdWriter {
            self.files.release_cold_observations();
        }
        // Close in the arena if free within the last budget, else one try; `db` closes
        // first. Missing it is safe: the host sets NO_CKPT_ON_CLOSE on these roles
        // (native_sql::retain_wal), so this close never checkpoints the WAL.
        if self.role.opens_in_arena() {
            let reader = self.role == ConnectionRole::QueryReader;
            let free = Reservation::acquire(reader, self.until).ok();
            self.arena = free.or_else(|| Reservation::try_now(reader));
        }
    }
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
        // Native adapters open and close inside the arena (WAL startup and
        // checkpoint locks race otherwise). Queries then read their snapshot
        // outside it; the maintenance writer takes it per transaction.
        let reader = role == ConnectionRole::QueryReader;
        let _opening = role
            .opens_in_arena()
            .then(|| Reservation::acquire(reader, deadline));
        let _opening = _opening.transpose()?;
        files.validate_database(&pin)?;
        let mut db = open(&pin, role, deadline)?;
        files.configure_connection_role(&mut db, role)?;
        configure_limits(&db, role, profile)?;
        finite(&mut db, deadline, "open validation", |db, _| {
            schema::validate(db, &id)?;
            if role.writable() && role != ConnectionRole::MaintenanceWriter {
                schema::validate_integrity(db)?;
            }
            Ok(())
        })?;
        configure_access(&db, role)?;
        if role == ConnectionRole::CandidateReader {
            finite(&mut db, deadline, "candidate integrity", |db, _| {
                schema::validate_integrity(db)
            })?;
        }
        files.validate_database(&pin)?;
        Ok(Some(Self {
            db,
            files,
            pin,
            identity: id,
            role,
            arena: None,
            _slot: slot,
            until: deadline,
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
            finite(&mut db, deadline, "epoch initialization", |db, _| {
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
            if role == ConnectionRole::ColdWriter {
                // A fresh cold epoch is private until its final durable checkpoint.
                set_synchronous(&db, "OFF", 0)?;
            }
            files.validate_database(&pin)?;
            Ok(db)
        })();
        let db = match initialized {
            Ok(db) => db,
            Err(original) => {
                files.release_creation_guard();
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
            until: deadline,
        })
    }
    pub fn validate(&mut self, deadline: Instant) -> AtlasResult<()> {
        self.files.validate_database(&self.pin)?;
        finite(&mut self.db, deadline, "identity validation", |db, _| {
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
        self.until = deadline;
        let _arena = if self.arena.is_none()
            && matches!(
                self.role,
                ConnectionRole::HostReader
                    | ConnectionRole::HostWriter
                    | ConnectionRole::MaintenanceWriter
            ) {
            Some(Reservation::acquire(
                self.role == ConnectionRole::HostReader,
                deadline,
            )?)
        } else {
            None
        };
        self.files.validate_database(&self.pin)?;
        if write {
            let mut wal = self.files.wal_bytes(&self.pin)?;
            if growth <= WAL_STOP && wal.saturating_add(growth) > WAL_STOP {
                // One renewal quantum can commit several transactions on the
                // same connection. Reclaim earlier commits before refusing the
                // next one; pinned readers still have to pass the size check.
                if !self.checkpoint_held(deadline)? {
                    // A query snapshot outlasted the busy wait: yield; the next admission retries.
                    return Err(stage_timeout("WAL checkpoint behind a query", 0));
                }
                wal = self.files.wal_bytes(&self.pin)?;
            }
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
        let before = if write && self.role == ConnectionRole::ColdWriter {
            self.files.written_pages(&self.db)
        } else {
            None
        };
        let result = finite(&mut self.db, deadline, "transaction", |db, budget_ms| {
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
            let expired = crate::clock::now() >= deadline;
            let result = match (result, changed, expired) {
                (Err(error), _, true)
                    if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) =>
                {
                    Err(error)
                }
                (_, _, true) => Err(stage_timeout("transaction", budget_ms)),
                (Ok(value), Ok(()), false) => Ok(value),
                (Err(e), _, false) | (_, Err(e), false) => Err(e),
            };
            if result.is_ok() && write {
                transaction.commit().map_err(cache_error)?;
            } else {
                transaction.rollback().map_err(cache_error)?;
            }
            result
        });
        if write && self.role == ConnectionRole::ColdWriter {
            let pages = if result.is_ok() {
                before.and_then(|before| {
                    self.files
                        .written_pages(&self.db)
                        .and_then(|after| after.checked_sub(before))
                })
            } else {
                None
            };
            self.files.record_written_pages(pages);
        }
        result
    }
    /// Event/commit/drain driven only. External pinned snapshots keep writes
    /// suspended; no timer or forced reader expiry is introduced.
    /// TRUNCATE checkpoint at 4 MB of WAL, inside the arena. An open query snapshot
    /// makes it return `false` after the 25 ms busy wait; the next write retries.
    pub fn checkpoint(&mut self, deadline: Instant) -> AtlasResult<bool> {
        let _arena = Reservation::acquire(false, deadline)?;
        self.checkpoint_held(deadline)
    }
    fn checkpoint_held(&mut self, deadline: Instant) -> AtlasResult<bool> {
        if !self.role.writable() {
            return Err(cache_error("reader cannot checkpoint"));
        }
        let wal = self.files.wal_bytes(&self.pin)?;
        if crate::clock::now() >= deadline {
            return Err(stage_timeout("WAL checkpoint admission", 0));
        }
        if wal < 4_000_000 {
            return Ok(true);
        }
        finite(&mut self.db, deadline, "WAL checkpoint", |db, _| {
            let (busy, _, _): (i64, i64, i64) = db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(cache_error)?;
            Ok(busy == 0)
        })
    }
    /// Restore durability before writing the final cold-epoch metadata.
    pub fn prepare_cold_publication(&mut self) -> AtlasResult<()> {
        if self.role != ConnectionRole::ColdWriter {
            return Err(cache_error(
                "cold publication requires the contained writer",
            ));
        }
        self.files.finish_creation_guard();
        self.files.validate_database(&self.pin)?;
        set_synchronous(&self.db, "FULL", 2)
    }
    /// Flush the final metadata and all prior cold writes before adoption.
    pub fn finish_cold_publication(&mut self, deadline: Instant) -> AtlasResult<()> {
        if self.role != ConnectionRole::ColdWriter {
            return Err(cache_error(
                "cold publication requires the contained writer",
            ));
        }
        self.files.validate_database(&self.pin)?;
        let synchronous: i64 = self
            .db
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(cache_error)?;
        if synchronous != 2 || self.files.wal_bytes(&self.pin)? <= 32 {
            return Err(cache_error(
                "durable cold publication requires final WAL frames",
            ));
        }
        let busy = finite(&mut self.db, deadline, "publication checkpoint", |db, _| {
            let (busy, _, _): (i64, i64, i64) = db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(cache_error)?;
            Ok(busy)
        })?;
        if busy != 0 {
            return Err(cache_error("cold publication checkpoint remains busy"));
        }
        self.files.validate_database(&self.pin)
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
        finite(&mut self.db, deadline, "cold memory release", |db, _| {
            db.release_memory().map_err(cache_error)
        })
    }
}
fn set_synchronous(db: &Connection, setting: &str, expected: i64) -> AtlasResult<()> {
    db.pragma_update(None, "synchronous", setting)
        .map_err(cache_error)?;
    let actual: i64 = db
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(cache_error)?;
    if actual != expected {
        return Err(cache_error("SQLite synchronous setting readback differs"));
    }
    Ok(())
}
fn open(pin: &DatabasePin, role: ConnectionRole, deadline: Instant) -> AtlasResult<Connection> {
    if crate::clock::now() >= deadline {
        return Err(stage_timeout("connection open", 0));
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
    // The verbatim exception is decided before ancestor resolution: only the
    // verbatim prefix cannot honour NOFOLLOW, and a Unix path resolved by
    // trusted_path keeps the guard on the database name itself.
    let verbatim = target != pin.path;
    // SQLite's NOFOLLOW refuses a symlinked ancestor outright (extended code
    // 1550), which breaks the ordinary macOS temp directory under /var. The
    // state-files walk admits only root- or current-user-owned link
    // ancestors; resolve that same rule here and hand SQLite the resolved
    // path, leaving NOFOLLOW to own the database name itself.
    let target = crate::trusted_path::resolve(&target).map_err(cache_error)?;
    // SQLite's NOFOLLOW refuses a verbatim path it cannot resolve with its own
    // walk; the retained pin already names the exact file, so the flag is
    // dropped only for the verbatim form.
    let symlink_guard = if verbatim {
        OpenFlags::empty()
    } else {
        OpenFlags::SQLITE_OPEN_NOFOLLOW
    };
    let mut db = Connection::open_with_flags(
        &target,
        flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_EXRESCODE | symlink_guard,
    )
    .map_err(cache_error)?;
    db.busy_timeout(
        deadline
            .saturating_duration_since(crate::clock::now())
            .min(Duration::from_millis(25)),
    )
    .map_err(cache_error)?;
    if role == ConnectionRole::ColdWriter {
        // This epoch is unpublished and has exactly one contained writer.
        // Exclusive WAL uses an in-process index, never a mapped -shm file.
        // Host handles retain normal locking after exact child reap/close.
        finite(&mut db, deadline, "cold locking setup", |db, _| {
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
        if db.limit(limit).map_err(cache_error)? > value {
            return Err(cache_error(
                "SQLite connection limit readback exceeds its bound",
            ));
        }
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
        (
            "cache_size",
            if role == ConnectionRole::ColdWriter {
                488
            } else {
                16
            },
        ),
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
    stage: &str,
    work: impl FnOnce(&Connection, u64) -> AtlasResult<T>,
) -> AtlasResult<T> {
    let remaining = deadline.saturating_duration_since(crate::clock::now());
    if remaining.is_zero() {
        return Err(stage_timeout(stage, 0));
    }
    // A busy wait (a reader's snapshot, a checkpoint) ends within this budget.
    db.busy_timeout(remaining.min(Duration::from_millis(25)))
        .map_err(cache_error)?;
    let budget_ms = ceil_ms(remaining);
    db.progress_handler(1000, Some(move || crate::clock::now() >= deadline))
        .map_err(cache_error)?;
    let result = work(db, budget_ms);
    db.progress_handler(0, None::<fn() -> bool>)
        .map_err(cache_error)?;
    match result {
        Err(error) if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) => {
            Err(error)
        }
        _ if crate::clock::now() >= deadline => Err(stage_timeout(stage, budget_ms)),
        result => result,
    }
}
pub(crate) fn timeout(budget_ms: u64) -> se_types::SeError {
    stage_timeout("query admission", budget_ms)
}

pub(crate) fn stage_timeout(stage: &str, budget_ms: u64) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::DeadlineExceeded(
        se_types::details::DeadlineExceeded {
            op: format!("Atlas SQL {stage}"),
            deadline_ms: budget_ms,
        },
    ))
}

/// Report a bounded SQL phase using its actual allowance and elapsed time.
pub fn timeout_phase(phase: &str, budget: Duration, elapsed: Duration) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::DeadlineExceeded(
        se_types::details::DeadlineExceeded {
            op: format!("Atlas SQL {phase} (elapsed {} ms)", ceil_ms(elapsed)),
            deadline_ms: ceil_ms(budget),
        },
    ))
}
fn ceil_ms(duration: Duration) -> u64 {
    let whole = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    whole.saturating_add(u64::from(
        !duration.subsec_nanos().is_multiple_of(1_000_000),
    ))
}

#[cfg(test)]
#[path = "statement_tests.rs"]
mod statement_tests;

#[cfg(test)]
mod tests;
