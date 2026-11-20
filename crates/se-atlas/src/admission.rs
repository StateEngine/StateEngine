//! Process-wide SQL admission. One reader and one writer connection match the
//! qualified two-connection memory profile, and one SQL/result arena serializes the
//! work that must not overlap. Queries read their WAL snapshot outside it.
use crate::cache::connection::{ConnectionRole, stage_timeout, timeout_phase};
use crate::errors::{AtlasResult, cache_error, capacity};
use std::{
    sync::{
        Condvar, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Instant,
};
static SLOTS: AtomicU8 = AtomicU8::new(0);
static READER_WAIT: Mutex<()> = Mutex::new(());
static READER_READY: Condvar = Condvar::new();
const READER_SLOT: u8 = 1;
const WRITER_SLOT: u8 = 2;
pub(crate) struct Slot(u8);
impl Slot {
    pub(crate) fn take(role: ConnectionRole, deadline: Instant) -> AtlasResult<Self> {
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
                let mut wait = remaining;
                if role != ConnectionRole::QueryReader {
                    // An idle retained query reader yields the slot; a busy one
                    // finishes its query first, which signals nobody, so poll.
                    // Its close takes READER_WAIT, so release it meanwhile.
                    drop(guard);
                    crate::reader::release_if_idle();
                    guard = READER_WAIT
                        .lock()
                        .map_err(|_| cache_error("Atlas reader slot lock poisoned"))?;
                    if SLOTS.load(Ordering::Acquire) & bit == 0 {
                        break;
                    }
                    wait = remaining.min(std::time::Duration::from_millis(10));
                }
                guard = READER_READY
                    .wait_timeout(guard, wait)
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

struct State {
    held: bool,
    readers: u32,
}
static STATE: Mutex<State> = Mutex::new(State {
    held: false,
    readers: 0,
});
static READY: Condvar = Condvar::new();

pub(crate) struct Reservation;
impl Reservation {
    pub(crate) fn acquire(reader: bool, deadline: Instant) -> AtlasResult<Self> {
        let started = Instant::now();
        let wait_deadline = crate::clock::wait_deadline(deadline);
        let budget = wait_deadline.saturating_duration_since(started);
        let mut state = STATE
            .lock()
            .map_err(|_| cache_error("Atlas query arena lock poisoned"))?;
        if reader {
            state.readers = state
                .readers
                .checked_add(1)
                .ok_or_else(|| cache_error("Atlas query arena waiter count exhausted"))?;
        }
        let mut waited = false;
        while state.held || (!reader && state.readers != 0) {
            waited = true;
            let remaining = wait_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            state = READY
                .wait_timeout(state, remaining)
                .map_err(|_| cache_error("Atlas query arena wait poisoned"))?
                .0;
        }
        if reader {
            state.readers -= 1;
        }
        if crate::clock::now() >= deadline || (waited && Instant::now() >= wait_deadline) {
            READY.notify_all();
            return Err(if !reader || budget.is_zero() {
                stage_timeout("query arena admission", 0)
            } else {
                timeout_phase("query arena admission", budget, started.elapsed())
            });
        }
        state.held = true;
        Ok(Self)
    }
    pub(crate) fn try_now(reader: bool) -> Option<Self> {
        let mut state = STATE.lock().ok()?;
        (!state.held && (reader || state.readers == 0)).then(|| state.held = true)?;
        Some(Self)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        // Preserve poisoning for the next caller, while releasing an arena
        // owned by this guard so an error cannot strand unrelated requests.
        let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
        state.held = false;
        READY.notify_all();
    }
}
