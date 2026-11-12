//! Background WAL maintenance: idle checkpoints run on a dedicated connection
//! in a dedicated thread, so checkpoint I/O never shares the writer task.
//! PASSIVE in WAL mode does not block the writer, and a slow checkpoint must
//! not stall appends either. The cadence is small and frequent, so the WAL is
//! kept far below the 64 MiB capacity cutoff instead of accumulating toward it.
use super::checkpoint::probe;
use super::*;
use crate::backup_context::MAX_WAL_BYTES;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
/// Background maintenance cadence: the former writer idle gap.
const TICK: Duration = Duration::from_millis(250);
/// The background connection must not queue long behind the writer's locks:
/// on contention the checkpoint reports busy and retries on the next tick.
const BUSY_TIMEOUT: Duration = Duration::from_millis(250);
/// Interruptible sleep granularity so the task exits promptly on close.
const WAKE: Duration = Duration::from_millis(25);
/// A fully-checkpointed WAL at least this large is worth resetting the file
/// for; below it the frames are negligible and the next real reset is closer.
const RESET_MIN_FRAMES: i64 = 256;

#[derive(Default)]
struct State {
    /// The last checkpoint left frames an active reader still pins.
    pending: AtomicBool,
    /// The last checkpoint attempt failed and awaits its retry.
    failed: AtomicBool,
}
/// Receipt-visible maintenance state shared between the task and the writer.
/// The idle flag is set by the writer around its blocking receive: the task
/// performs checkpoint I/O only while the writer has no command in flight, so
/// a checkpoint never contends with a queued commit for the WAL write lock.
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
        self.state.pending.load(Ordering::Acquire)
    }
    pub(crate) fn failed(&self) -> bool {
        self.state.failed.load(Ordering::Acquire)
    }
    pub(crate) fn set_idle(&self, idle: bool) {
        self.idle.store(idle, Ordering::Release);
    }
    fn idle(&self) -> bool {
        self.idle.load(Ordering::Acquire)
    }
    fn set(&self, pending: bool, failed: bool) {
        self.state.failed.store(failed, Ordering::Release);
        self.state.pending.store(pending, Ordering::Release);
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
    /// next wake, so the host is never returned with a stray connection.
    pub(crate) fn spawn(
        path: PathBuf,
        timeout: Duration,
        context: BackupContext,
    ) -> StoreResult<Self> {
        let status = Status::default();
        let closed = Arc::new(AtomicBool::new(false));
        let (task_status, task_closed) = (status.clone(), closed.clone());
        let handle = std::thread::Builder::new()
            .name("se-store-checkpoint".into())
            .spawn(move || run(path, timeout, context, task_closed, task_status))
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
        // own connection; the hard WAL cutoff keeps the store honest meanwhile.
        self.signal();
    }
}
fn run(
    path: PathBuf,
    timeout: Duration,
    context: BackupContext,
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
            Err(_) => {
                status.set(true, true);
                sleep_wake(&closed);
                continue;
            }
        };
        if db.busy_timeout(BUSY_TIMEOUT).is_err() {
            status.set(true, true);
            sleep_wake(&closed);
            continue;
        }
        tick(&db, &context, &status);
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
fn tick(db: &Connection, context: &BackupContext, status: &Status) {
    if !status.idle() {
        // The writer has traffic: checkpoint I/O now would fight its commits
        // for the WAL write lock and push them past the busy timeout.
        return;
    }
    let wal = match probe(db) {
        Ok(wal) => wal,
        Err(_) => {
            status.set(true, true);
            return;
        }
    };
    if wal.log == 0 {
        status.set(false, false);
        return;
    }
    if context.suppress_checkpoint(wal.log, wal.bytes >= MAX_WAL_BYTES) {
        status.set(true, false);
        return;
    }
    let hard = wal.bytes >= MAX_WAL_BYTES;
    if hard || (wal.log == wal.done && wal.log >= RESET_MIN_FRAMES) {
        // The capacity cut, or every frame already in the main database: the
        // only remaining work is resetting the file. PASSIVE never resets a
        // WAL it copies no frames from, so without this step a stranded WAL
        // would keep its high-water size until the next full reset.
        if !status.idle() {
            return;
        }
        match checkpoint(db, "TRUNCATE") {
            Ok((_, log, _)) => status.set(log > 0, false),
            Err(_) => status.set(true, true),
        }
        return;
    }
    // Fully checkpointed and small: nothing to do, and no debt left behind.
    if wal.log == wal.done {
        status.set(false, false);
        return;
    }
    if !status.idle() {
        return;
    }
    // New frames to copy: PASSIVE is the mode that never waits on a reader in
    // the WAL, reporting busy instead.
    let result = checkpoint(db, "PASSIVE");
    match result {
        Ok((busy, log, done)) if busy == 0 && done == log => {
            // The copy completed fully, so reset the file to zero now instead
            // of leaving it at its high-water size until an idle gap.
            match checkpoint(db, "TRUNCATE") {
                Ok((_, log, _)) => status.set(log > 0, false),
                Err(_) => status.set(true, true),
            }
        }
        Ok((busy, log, done)) => status.set(busy != 0 || log > done, false),
        Err(_) => status.set(true, true),
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
