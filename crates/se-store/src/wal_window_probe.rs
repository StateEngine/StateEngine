//! Experimental two-endmark producer window; never enabled by a shipped default.
use crate::{
    BackupContext, LeaseMode, RuntimeLease, StoreError, StoreErrorCode, StoreResult,
    checkpoint_task::{Maint, Status},
    connection,
    error::*,
    transaction::checkpoint::{Gate, probe},
    wal_probe_trace::{checkpoint, record},
};
use rusqlite::Connection;
use serde_json::json;
use std::{
    collections::VecDeque,
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const FRAMES: i64 = 256;
struct Pin {
    db: Connection,
    end: i64,
    maximum_group: i64,
    copied: bool,
}
#[derive(Default)]
struct State {
    pins: VecDeque<Pin>,
    last_log: Option<i64>,
    chunk_start: i64,
    maximum_group: i64,
    paused: bool,
    failed: Option<Box<StoreError>>,
}
#[derive(Default)]
pub(crate) struct Window {
    state: Mutex<State>,
    changed: Condvar,
}
impl Window {
    pub(crate) fn wake(&self) {
        let _guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.changed.notify_all();
    }
    pub(crate) fn before_group(&self, db: &Connection, timeout: Duration) -> StoreResult<()> {
        let start = Instant::now();
        let deadline = start + timeout;
        let mut state = self.state.lock().map_err(invalid)?;
        if state.last_log.is_none() {
            let wal = probe(db)?;
            state.last_log = Some(wal.log.max(0));
            state.chunk_start = wal.done.max(0);
        }
        if state.pins.len() == 2 {
            state.paused = true;
            self.changed.notify_all();
        }
        while state.paused && state.failed.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(fail(
                    StoreErrorCode::Busy,
                    "probe producer window did not complete before busy deadline",
                ));
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(invalid)?
                .0;
        }

        state.failed.clone().map_or(Ok(()), Err)
    }
    pub(crate) fn committed(
        &self,
        db: &Connection,
        path: &Path,
        timeout: Duration,
    ) -> StoreResult<()> {
        let wal = probe(db)?;
        let mut state = self.state.lock().map_err(invalid)?;
        let previous = state.last_log.unwrap_or(wal.done.max(0));
        if wal.log < previous {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "probe WAL generation changed while own endmark was retained",
            ));
        }
        state.maximum_group = state.maximum_group.max(wal.log - previous);
        state.last_log = Some(wal.log);
        if wal.log - state.chunk_start >= FRAMES {
            if state.pins.len() >= 2 {
                return Err(fail(
                    StoreErrorCode::Unreadable,
                    "probe exceeded its two-pin producer window",
                ));
            }
            let pin = connection::connect(path, false, timeout)?;
            connection::begin_snapshot(&pin, path)?;
            let actual = connection::header(&pin)?;
            let expected = connection::header(db)?;
            if actual != expected {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "probe read pin changed store identity",
                ));
            }
            let maximum_group = state.maximum_group;
            record(
                json!({"kind":"capture", "start":state.chunk_start,"end":wal.log,
                "maximum_group":maximum_group,"pins":state.pins.len()+1}),
            )?;
            state.pins.push_back(Pin {
                db: pin,
                end: wal.log,
                maximum_group,
                copied: false,
            });
            state.chunk_start = wal.log;
            state.maximum_group = 0;
            self.changed.notify_all();
        }
        Ok(())
    }
    fn retire(state: &mut State) -> StoreResult<()> {
        if let Some(pin) = state.pins.pop_front() {
            pin.db.execute_batch("ROLLBACK").map_err(sql)?;
            pin.db.close().map_err(|(_, error)| sql(error))?;
        }
        Ok(())
    }
    fn turn(&self, db: &Connection) -> StoreResult<()> {
        let (target, maximum_group, reset) = {
            let mut state = self.state.lock().map_err(invalid)?;
            if state.pins.len() == 2 && state.pins.front().is_some_and(|p| p.copied) {
                Self::retire(&mut state)?;
            }
            let Some(pin) = state.pins.front() else {
                return Ok(());
            };
            (pin.end, pin.maximum_group, pin.copied && state.paused)
        };
        if reset {
            let wal = probe(db)?;
            if wal.log != target || wal.done != target {
                return Err(fail(
                    StoreErrorCode::Unreadable,
                    "probe reset would copy uncopied frames",
                ));
            }
            {
                let mut state = self.state.lock().map_err(invalid)?;
                while !state.pins.is_empty() {
                    Self::retire(&mut state)?;
                }
            }
            let result = checkpoint(db, "TRUNCATE", "window-reset")?;
            if result != (0, 0, 0) {
                return Err(fail(
                    StoreErrorCode::Busy,
                    "probe synchronized reset remains pinned",
                ));
            }
            let mut state = self.state.lock().map_err(invalid)?;
            state.last_log = Some(0);
            state.chunk_start = 0;
            state.maximum_group = 0;
            state.paused = false;
            self.changed.notify_all();
            return Ok(());
        }
        let before = probe(db)?;
        let (busy, log, done) = checkpoint(db, "PASSIVE", "window-copy")?;
        record(
            json!({"kind":"window-copy", "target":target,"before_done":before.done,
            "log":log,"done":done,"busy":busy,"maximum_group":maximum_group,
            "bound":FRAMES+maximum_group,"advance":done-before.done}),
        )?;
        if done > target || done < before.done || done - before.done > FRAMES + maximum_group {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "probe copied-frame bound failed",
            ));
        }
        if busy == 0 && done == target {
            let mut state = self.state.lock().map_err(invalid)?;
            let pin = state
                .pins
                .front_mut()
                .ok_or_else(|| invalid("probe lost oldest pin"))?;
            if pin.end != target {
                return Err(invalid("probe target changed"));
            }
            pin.copied = true;
            self.changed.notify_all();
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    pub(crate) fn run(
        &self,
        options: (&Path, Duration),
        context: &BackupContext,
        lease: &Arc<dyn RuntimeLease>,
        closed: &AtomicBool,
        gate: &Gate,
        status: &Status,
    ) {
        let (path, timeout) = options;
        let result = (|| -> StoreResult<()> {
            while !closed.load(Ordering::Acquire) {
                let mut state = self.state.lock().map_err(invalid)?;
                while !closed.load(Ordering::Acquire)
                    && state.failed.is_none()
                    && !state
                        .pins
                        .front()
                        .is_some_and(|p| !p.copied || state.pins.len() == 2 || state.paused)
                {
                    state = self.changed.wait(state).map_err(invalid)?;
                }
                if closed.load(Ordering::Acquire) {
                    break;
                }
                if state.failed.is_some() {
                    let _guard = self.changed.wait(state).map_err(invalid)?;
                    continue;
                }
                drop(state);
                let result = (|| {
                    // Match the existing worker: a fresh writable connection per turn.
                    let db = connection::connect(path, true, timeout)?;
                    db.busy_timeout(Duration::from_millis(10)).map_err(sql)?;
                    let (store, generation) = connection::lease_state(&db)?;
                    connection::validate_lease_state(
                        &store,
                        generation,
                        &lease.identity()?,
                        LeaseMode::Host,
                    )?;
                    let wal = probe(&db)?;
                    if context.suppress_checkpoint(
                        wal.log,
                        wal.bytes >= crate::backup_context::MAX_WAL_BYTES,
                    ) {
                        status.set(Maint::Pending);
                        std::thread::sleep(Duration::from_millis(10));
                        return Ok(());
                    }
                    let _permit = gate.acquire(Duration::from_millis(10))?;
                    self.turn(&db)
                })();
                if let Err(error) = result {
                    record(json!({"kind":"window-error","cause":error.to_string()}))?;
                    self.state.lock().map_err(invalid)?.failed = Some(error.clone());
                    status.set(Maint::Failed(error));
                    self.changed.notify_all();
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            status.set(Maint::Failed(error));
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.pins.is_empty() {
            if let Err(error) = Self::retire(&mut state) {
                status.set(Maint::Failed(error));
            }
        }
        if let Err(error) = record(json!({"kind":"window-stopped","pins":state.pins.len()})) {
            status.set(Maint::Failed(error));
        }
        self.changed.notify_all();
    }
}
