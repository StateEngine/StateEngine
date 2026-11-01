//! One immutable reader budget shared by snapshots, private lookups and backups.
use crate::{StoreErrorCode, StoreResult, error::*};
use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone)]
pub(crate) struct ReadSlots(Arc<State>);
struct State {
    capacity: usize,
    used: AtomicUsize,
}
pub(crate) struct ReadSlot(Arc<State>);

impl Default for ReadSlots {
    fn default() -> Self {
        Self::with_limit(2)
    }
}
impl ReadSlots {
    pub(crate) fn new(capacity: NonZeroU32) -> StoreResult<Self> {
        if !(2..=8).contains(&capacity.get()) {
            return Err(invalid("reader capacity must be between 2 and 8 inclusive"));
        }
        Ok(Self::with_limit(capacity.get() as usize))
    }
    fn with_limit(capacity: usize) -> Self {
        Self(Arc::new(State {
            capacity,
            used: AtomicUsize::new(0),
        }))
    }
    pub(crate) fn acquire(&self) -> StoreResult<ReadSlot> {
        self.0
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < self.0.capacity).then_some(used + 1)
            })
            .map_err(|_| {
                fail(
                    StoreErrorCode::Backpressure,
                    format!(
                        "all {} finite store read slots are already in use",
                        self.0.capacity
                    ),
                )
            })?;
        Ok(ReadSlot(Arc::clone(&self.0)))
    }
}
impl Drop for ReadSlot {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}
