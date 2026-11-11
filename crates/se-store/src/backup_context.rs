use crate::{error::*, *};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
pub(crate) const MAX_WAL_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) struct State {
    pub store: StoreId,
    pub incarnation: u64,
    pub generation: u64,
    pub path: PathBuf,
    pub slots: crate::read_slots::ReadSlots,
    pub pending: AtomicBool,
    pub pinned: AtomicBool,
    pub abort: AtomicBool,
}
pub(crate) struct Pin(BackupContext);
impl Drop for Pin {
    fn drop(&mut self) {
        self.0.state.abort.store(false, Ordering::Release);
        self.0.state.pinned.store(false, Ordering::Release);
        self.0.state.pending.store(false, Ordering::Release);
    }
}
impl BackupContext {
    pub(crate) fn bound(
        info: &StoreInfo,
        generation: u64,
        path: PathBuf,
        slots: crate::read_slots::ReadSlots,
    ) -> Self {
        Self {
            state: Arc::new(State {
                store: info.id.clone(),
                incarnation: info.incarnation,
                generation,
                path,
                slots,
                pending: AtomicBool::new(false),
                pinned: AtomicBool::new(false),
                abort: AtomicBool::new(false),
            }),
        }
    }
    pub(crate) fn pin(
        &self,
        info: &StoreInfo,
        lease: &LeaseIdentity,
        path: &std::path::Path,
    ) -> StoreResult<Pin> {
        if info.id != self.state.store
            || info.incarnation != self.state.incarnation
            || lease.generation != self.state.generation
            || lease.mode != LeaseMode::Host
            || self.state.path != path
        {
            return Err(fail(
                StoreErrorCode::GenerationChanged,
                "backup context/store/path/generation differs",
            ));
        }
        self.state
            .pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                fail(
                    StoreErrorCode::Backpressure,
                    "one backup generation is already pending",
                )
            })?;
        self.state.abort.store(false, Ordering::Release);
        self.state.pinned.store(true, Ordering::Release);
        Ok(Pin(self.clone()))
    }
    pub(crate) fn suppress_checkpoint(&self, wal_frames: i64, hard: bool) -> bool {
        if !self.state.pinned.load(Ordering::Acquire) {
            return false;
        }
        if hard || wal_frames >= 16384 {
            self.state.abort.store(true, Ordering::Release);
        }
        true
    }
}

impl Pin {
    pub(crate) fn release_reader(&self) {
        self.0.state.pinned.store(false, Ordering::Release);
    }
}
