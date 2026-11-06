//! One SQL/result arena, with bounded foreground waiting instead of a refusal
//! when the maintenance writer is finishing its current transaction.
use super::timeout;
use crate::{errors::AtlasResult, errors::cache_error};
use std::{
    sync::{Condvar, Mutex},
    time::Instant,
};

struct State {
    held: bool,
    readers: u32,
}
static STATE: Mutex<State> = Mutex::new(State {
    held: false,
    readers: 0,
});
static READY: Condvar = Condvar::new();

pub(super) struct Reservation;
impl Reservation {
    pub(super) fn acquire(reader: bool, deadline: Instant) -> AtlasResult<Self> {
        let mut state = STATE
            .lock()
            .map_err(|_| cache_error("Atlas query arena lock poisoned"))?;
        if reader {
            state.readers = state
                .readers
                .checked_add(1)
                .ok_or_else(|| cache_error("Atlas query arena waiter count exhausted"))?;
        }
        while state.held || (!reader && state.readers != 0) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if reader {
                    state.readers -= 1;
                }
                READY.notify_all();
                return Err(timeout(0));
            }
            state = READY
                .wait_timeout(state, remaining)
                .map_err(|_| cache_error("Atlas query arena wait poisoned"))?
                .0;
        }
        if reader {
            state.readers -= 1;
        }
        if Instant::now() >= deadline {
            READY.notify_all();
            return Err(timeout(0));
        }
        state.held = true;
        Ok(Self)
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
