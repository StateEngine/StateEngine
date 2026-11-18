//! Background WAL maintenance: checkpoints run on a dedicated connection
//! in a dedicated thread, so checkpoint I/O never shares the writer task.
//! PASSIVE in WAL mode does not block the writer, and a slow checkpoint must
//! not stall appends either. WAL growth can request PASSIVE copying during
//! traffic; the quiet interval still owns background resets and idle cleanup.
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
    time::{Duration, Instant},
};
/// Require a quiet interval before checkpoint I/O; brief request gaps are traffic.
const TICK: Duration = Duration::from_millis(250);
/// Lock-contention backoff for the background connection. A busy reader
/// defers maintenance to another quiet interval. This bounds SQLite's lock
/// wait, not filesystem I/O after the checkpoint has acquired its locks.
const BACKOFF: Duration = Duration::from_millis(10);
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
/// Idle edges coalesce into a quiet interval for cleanup; growth edges allow
/// PASSIVE copying while traffic continues. Neither condition holds its lock
/// over SQLite work, and a settled host has no periodic maintenance wakes.
#[derive(Clone)]
pub(crate) struct Status {
    state: Arc<State>,
    idle: Arc<AtomicBool>,
    wake: crate::checkpoint_wake::Wake,
}
impl Default for Status {
    fn default() -> Self {
        // Busy until the writer proves the channel empty: a fresh host has
        // startup traffic, and the hard cutoff stays the fail-safe meanwhile.
        Self {
            state: Arc::default(),
            idle: Arc::new(AtomicBool::new(false)),
            wake: crate::checkpoint_wake::Wake::default(),
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
        if idle {
            self.wake();
        }
    }
    fn idle(&self) -> bool {
        self.idle.load(Ordering::Acquire)
    }
    pub(crate) fn wake(&self) {
        self.wake.idle();
    }
    pub(crate) fn wake_handle(&self) -> crate::checkpoint_wake::Wake {
        self.wake.clone()
    }
    fn wait(&self, closed: &AtomicBool, cap: Option<Duration>) -> bool {
        self.wake.wait(closed, cap, TICK)
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
        gate: crate::transaction::checkpoint::Gate,
    ) -> StoreResult<Self> {
        let status = Status::default();
        let closed = Arc::new(AtomicBool::new(false));
        let (task_status, task_closed) = (status.clone(), closed.clone());
        let handle = std::thread::Builder::new()
            .name("se-store-checkpoint".into())
            .spawn(move || {
                run(
                    path,
                    timeout,
                    context,
                    lease,
                    task_closed,
                    task_status,
                    gate,
                )
            })
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
        // The task now sleeps until an edge, so shutdown must be an edge too;
        // otherwise drop would wait out an indefinite wait.
        self.status.wake();
    }
    pub(crate) fn join(mut self, deadline: Instant) -> StoreResult<()> {
        self.signal();
        while self
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
        {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                let mut error = fail(
                    StoreErrorCode::Busy,
                    "Background store maintenance did not stop within the drain deadline; storage closure is unproved.",
                );
                error.remedy = se_types::Remedy {
                    text: "Preserve the data home and resolve the storage delay, then restart the runtime process to recreate the maintenance task. For an embedded runtime, restart its owning application.".into(),
                    command: None,
                };
                // Drop signals the worker again. Its connection and lease stay
                // owned by that worker; no clean host is returned to the caller.
                return Err(error);
            };
            // Never enter the unbounded native join while the thread is live.
            std::thread::park_timeout(remaining.min(Duration::from_millis(1)));
        }
        if let Some(handle) = self.handle.take() {
            // A panicked task must read as Failed, never as a clean join:
            // once it is dead the drain report is the last word on the WAL,
            // and a swallowed panic would let that word be Clear.
            if let Err(payload) = handle.join() {
                let message = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("an unnameable panic payload");
                let mut error = fail(
                    StoreErrorCode::BackupFailed,
                    format!("checkpoint task panicked: {message}"),
                );
                // Only this site is the maintenance task's death; real backup
                // failures keep fail()'s shared remedy for their own cause.
                error.remedy = se_types::Remedy {
                    text: "Restart the runtime (`se down`, then `se up`) to recreate the background maintenance task; preserve the named cause and the store for diagnosis.".into(),
                    command: None,
                };
                self.status.set(Maint::Failed(error));
            }
        }
        Ok(())
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
    gate: crate::transaction::checkpoint::Gate,
) {
    if status.wait(&closed, None) {
        return;
    }
    loop {
        if closed.load(Ordering::Acquire) {
            return;
        }
        let growth = status.wake.take_growth();
        // Reopen until the first success so a transient lock at startup costs
        // one tick, not the whole maintenance lifetime.
        let db = match crate::connection::connect(&path, true, timeout) {
            Ok(db) => db,
            Err(error) => {
                status.set(Maint::Failed(error));
                if status.wait(&closed, Some(TICK)) {
                    return;
                }
                continue;
            }
        };
        if let Err(error) = db.busy_timeout(BACKOFF) {
            status.set(Maint::Failed(sql(error)));
            if status.wait(&closed, Some(TICK)) {
                return;
            }
            continue;
        }
        match gate.acquire(BACKOFF) {
            Ok(_permit) => tick(&db, &context, &lease, &status, growth),
            Err(_) => {
                // Contention leaves debt, but cannot clear a retained failure
                // without a successful maintenance tick.
                if !status.pending() {
                    status.set(Maint::Pending);
                }
            }
        }
        // Only owe work after a tick that left debt: frames a pinned reader
        // blocked, or a failure the next tick may clear. Anything else is the
        // no-op tick, and waiting for the next idle edge removes it.
        let owed = status.pending() || status.failed();
        if status.wait(&closed, owed.then_some(TICK)) {
            return;
        }
    }
}
fn tick(
    db: &Connection,
    context: &BackupContext,
    lease: &Arc<dyn RuntimeLease>,
    status: &Status,
    growth: bool,
) {
    if !growth && !status.idle() {
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
    if wal.log == wal.done && wal.log >= RESET_MIN_FRAMES {
        if growth {
            // Even a zero-copy reset takes the writer lock. Preserve it as
            // idle debt instead of doing it on a traffic-driven wake.
            status.set(Maint::Pending);
            return;
        }
        // Every frame is already in the main database: the only remaining
        // work is resetting the file, and a reset that copies no frames is
        // fast. PASSIVE never resets a WAL it copies no frames from, so
        // without this step a stranded WAL would keep its high-water size
        // until the next full reset. The short backoff bounds how long a
        // straggling write waits for it. A WAL at the 64 MiB capacity
        // cutoff with uncopied frames deliberately falls through to the
        // PASSIVE path below and pays for its copy in small yieldable
        // steps: a full TRUNCATE here would copy and reset 64 MiB in one
        // tick while holding the WAL lock, and under load that hold
        // collides with the writer's own inline cutoff until one side
        // exhausts its busy wait into a spurious refusal (#201). The
        // write path stays the sole owner of the capacity cut.
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
    if !growth && !status.idle() {
        return;
    }
    // New frames to copy: PASSIVE is the mode that never waits on a reader in
    // the WAL, reporting busy instead.
    match checkpoint(db, "PASSIVE") {
        Ok((busy, log, done)) if busy == 0 && done == log => {
            if growth {
                // A traffic-driven pass never escalates to TRUNCATE. SQLite
                // may reuse a fully backfilled log on the next write; idle
                // maintenance owns a reset that requires writer exclusion.
                status.set(if log >= RESET_MIN_FRAMES {
                    Maint::Pending
                } else {
                    Maint::Clear
                });
                return;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_records_a_panicked_task_as_failed() -> StoreResult<()> {
        let status = Status::default();
        let task = CheckpointTask {
            handle: Some(std::thread::spawn(|| panic!("planted checkpoint panic"))),
            closed: Arc::new(AtomicBool::new(false)),
            status: status.clone(),
        };
        task.join(Instant::now() + Duration::from_secs(2))?;
        assert!(
            status.failed(),
            "a dead task must read as Failed, never Clear"
        );
        let Some(error) = status.last_error() else {
            panic!("a failed join retains its error");
        };
        assert!(
            error.cause.contains("planted checkpoint panic"),
            "the panic message must be named, got: {}",
            error.cause
        );
        assert!(
            error
                .remedy
                .text
                .contains("recreate the background maintenance task"),
            "the maintenance remedy must name a working step, got: {}",
            error.remedy.text
        );
        Ok(())
    }
}
