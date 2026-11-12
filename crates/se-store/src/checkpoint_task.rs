//! Background WAL maintenance: idle checkpoints run on a dedicated connection
//! in a dedicated thread, so checkpoint I/O never shares the writer task.
//! PASSIVE in WAL mode does not block the writer, and a slow checkpoint must
//! not stall appends either. The cadence is small and frequent, so the WAL is
//! kept far below the 64 MiB capacity cutoff instead of accumulating toward it.
use crate::backup_context::MAX_WAL_BYTES;
use crate::transaction::checkpoint::probe;
use crate::{error::*, *};
use rusqlite::Connection;
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
/// Background maintenance cadence: the former writer idle gap.
const TICK: Duration = Duration::from_millis(250);
/// Lock-contention backoff for the background connection. On contention the
/// task yields the WAL write lock within this window and retries on the next
/// tick, so a write that slips in after the idle gate waits at most this long
/// for the checkpoint to back off, never for a checkpoint waiting on a pinned
/// reader.
const BACKOFF: Duration = Duration::from_millis(10);
/// Interruptible sleep granularity so the task exits promptly on close.
const WAKE: Duration = Duration::from_millis(25);
/// A fully-checkpointed WAL at least this large is worth resetting the file
/// for; below it the frames are negligible and the next real reset is closer.
const RESET_MIN_FRAMES: i64 = 256;
/// One maintenance fact, never two booleans: Clear owes nothing, Pending owes
/// a checkpoint, and Failed retains the last error for the flush report.
#[derive(Debug, Clone, Default)]
pub(crate) enum Maint {
    #[default]
    Clear,
    Pending,
    Failed(Box<StoreError>),
}
impl Maint {
    fn pending(&self) -> bool {
        !matches!(self, Self::Clear)
    }
    fn failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
    fn error(&self) -> Option<&StoreError> {
        match self {
            Self::Failed(error) => Some(error),
            _ => None,
        }
    }
}
#[derive(Default)]
struct State {
    cell: Mutex<Maint>,
}
impl State {
    fn lock(&self) -> MutexGuard<'_, Maint> {
        // The guard body copies or compares one small value and never panics;
        // recovering a poisoned guard keeps the flush report honest instead
        // of taking the maintenance path down with a sibling thread.
        self.cell
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
/// Receipt-visible maintenance state shared between the task and the writer.
/// The idle flag is set by the writer around its blocking receive: the task
/// performs checkpoint I/O only while the writer has no command in flight, so
/// a checkpoint contends with a queued commit only inside the short backoff
/// window a straggling write can enter after the idle gate.
#[derive(Clone)]
pub(crate) struct Status {
    state: Arc<State>,
    idle: Arc<AtomicBool>,
}
impl Default for Status {
    fn default() -> Self {
        // Busy until the writer proves the channel empty: a fresh host has
        // startup traffic, and the hard cutoff stays the fail-safe meanwhile.
        Self {
            state: Arc::default(),
            idle: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Status {
    pub(crate) fn pending(&self) -> bool {
        self.state.lock().pending()
    }
    pub(crate) fn failed(&self) -> bool {
        self.state.lock().failed()
    }
    /// The retained last maintenance error, or None while the debt is clean.
    pub(crate) fn last_error(&self) -> Option<Box<StoreError>> {
        self.state.lock().error().cloned().map(Box::new)
    }
    /// A writer-driven checkpoint completed fully: the pending debt the task
    /// observed (frames it could not copy yet) is paid on the writer's own
    /// connection, so the report reads clean. A retained Failed is a real
    /// task failure: only the task's own next successful tick clears it.
    pub(crate) fn clear_pending(&self) {
        let mut cell = self.state.lock();
        if matches!(*cell, Maint::Pending) {
            *cell = Maint::Clear;
        }
    }
    pub(crate) fn set_idle(&self, idle: bool) {
        self.idle.store(idle, Ordering::Release);
    }
    fn idle(&self) -> bool {
        self.idle.load(Ordering::Acquire)
    }
    fn set(&self, maint: Maint) {
        *self.state.lock() = maint;
    }
}
pub(crate) struct CheckpointTask {
    handle: Option<JoinHandle<()>>,
    closed: Arc<AtomicBool>,
    status: Status,
}
impl CheckpointTask {
    /// Already-exited placeholder for the drain's `mem::replace`; its signal
    /// is pre-set and its join is a no-op.
    pub(crate) fn detached() -> Self {
        Self {
            handle: None,
            closed: Arc::new(AtomicBool::new(true)),
            status: Status::default(),
        }
    }
}
impl CheckpointTask {
    /// Starts the task on its own writable connection. The task lives with the
    /// writer that owns it: drain joins it, and drop signals it to exit on its
    /// next wake, so the host is never returned with a stray connection. The
    /// writer's lease is carried so every tick re-checks the gate the writer
    /// itself is bound by.
    pub(crate) fn spawn(
        path: PathBuf,
        timeout: Duration,
        context: BackupContext,
        lease: Arc<dyn RuntimeLease>,
    ) -> StoreResult<Self> {
        let status = Status::default();
        let closed = Arc::new(AtomicBool::new(false));
        let (task_status, task_closed) = (status.clone(), closed.clone());
        let handle = std::thread::Builder::new()
            .name("se-store-checkpoint".into())
            .spawn(move || run(path, timeout, context, lease, task_closed, task_status))
            .map_err(invalid)?;
        Ok(Self {
            handle: Some(handle),
            closed,
            status,
        })
    }
    pub(crate) fn status(&self) -> &Status {
        &self.status
    }
    pub(crate) fn signal(&self) {
        self.closed.store(true, Ordering::Release);
    }
    pub(crate) fn join(mut self) {
        self.signal();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
impl Drop for CheckpointTask {
    fn drop(&mut self) {
        // Detached path: the task exits on its next wake check and closes its
        // own connection; the per-tick lease gate and the hard WAL cutoff keep
        // the store honest meanwhile.
        self.signal();
    }
}
fn run(
    path: PathBuf,
    timeout: Duration,
    context: BackupContext,
    lease: Arc<dyn RuntimeLease>,
    closed: Arc<AtomicBool>,
    status: Status,
) {
    loop {
        if closed.load(Ordering::Acquire) {
            return;
        }
        // Reopen until the first success so a transient lock at startup costs
        // one tick, not the whole maintenance lifetime.
        let db = match crate::connection::connect(&path, true, timeout) {
            Ok(db) => db,
            Err(error) => {
                status.set(Maint::Failed(error));
                sleep_wake(&closed);
                continue;
            }
        };
        if let Err(error) = db.busy_timeout(BACKOFF) {
            status.set(Maint::Failed(sql(error)));
            sleep_wake(&closed);
            continue;
        }
        tick(&db, &context, &lease, &status);
        if closed.load(Ordering::Acquire) {
            return;
        }
        sleep_wake(&closed);
    }
}
fn sleep_wake(closed: &Arc<AtomicBool>) {
    let mut slept = Duration::ZERO;
    while slept < TICK && !closed.load(Ordering::Acquire) {
        std::thread::sleep(WAKE);
        slept += WAKE;
    }
}
fn tick(db: &Connection, context: &BackupContext, lease: &Arc<dyn RuntimeLease>, status: &Status) {
    if !status.idle() {
        // The writer has traffic: checkpoint I/O now would fight its commits
        // for the WAL write lock and push them past the busy timeout.
        return;
    }
    // The writer validates its lease before every operation; the task mirrors
    // that gate before its own I/O so a tick that outlives the writer (the
    // detached drop window) cannot touch a store that has moved on.
    let (store, state) = match crate::connection::lease_state(db) {
        Ok(value) => value,
        Err(error) => {
            status.set(Maint::Failed(error));
            return;
        }
    };
    let identity = match lease.identity() {
        Ok(value) => value,
        Err(error) => {
            status.set(Maint::Failed(error));
            return;
        }
    };
    if let Err(error) =
        crate::connection::validate_lease_state(&store, state, &identity, LeaseMode::Host)
    {
        status.set(Maint::Failed(error));
        return;
    }
    let wal = match probe(db) {
        Ok(wal) => wal,
        Err(error) => {
            status.set(Maint::Failed(error));
            return;
        }
    };
    if wal.log == 0 {
        status.set(Maint::Clear);
        return;
    }
    if context.suppress_checkpoint(wal.log, wal.bytes >= MAX_WAL_BYTES) {
        status.set(Maint::Pending);
        return;
    }
    let hard = wal.bytes >= MAX_WAL_BYTES;
    if hard || (wal.log == wal.done && wal.log >= RESET_MIN_FRAMES) {
        // The capacity cut, or every frame already in the main database: the
        // only remaining work is resetting the file. PASSIVE never resets a
        // WAL it copies no frames from, so without this step a stranded WAL
        // would keep its high-water size until the next full reset. The short
        // backoff bounds how long a straggling write waits for it.
        if !status.idle() {
            return;
        }
        match checkpoint(db, "TRUNCATE") {
            Ok((_, log, _)) => status.set(if log > 0 {
                Maint::Pending
            } else {
                Maint::Clear
            }),
            Err(error) => status.set(Maint::Failed(error)),
        }
        return;
    }
    // Fully checkpointed and small: nothing to do, and no debt left behind.
    if wal.log == wal.done {
        status.set(Maint::Clear);
        return;
    }
    if !status.idle() {
        return;
    }
    // New frames to copy: PASSIVE is the mode that never waits on a reader in
    // the WAL, reporting busy instead.
    match checkpoint(db, "PASSIVE") {
        Ok((busy, log, done)) if busy == 0 && done == log => {
            // The copy completed fully, so reset the file to zero now instead
            // of leaving it at its high-water size until an idle gap.
            match checkpoint(db, "TRUNCATE") {
                Ok((_, log, _)) => status.set(if log > 0 {
                    Maint::Pending
                } else {
                    Maint::Clear
                }),
                Err(error) => status.set(Maint::Failed(error)),
            }
        }
        Ok((busy, log, done)) => status.set(if busy != 0 || log > done {
            Maint::Pending
        } else {
            Maint::Clear
        }),
        Err(error) => status.set(Maint::Failed(error)),
    }
}
fn checkpoint(db: &Connection, mode: &str) -> StoreResult<(i64, i64, i64)> {
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
