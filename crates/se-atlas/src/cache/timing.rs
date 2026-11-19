//! Diagnostic timing for the private cold writer.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub static ADMISSION_US: AtomicU64 = AtomicU64::new(0);
pub static PRIVATE_GUARD: AtomicU64 = AtomicU64::new(0);
pub static ACCOUNTING_ESTIMATES: AtomicU64 = AtomicU64::new(0);
pub static ACCOUNTING_REFRESHES: AtomicU64 = AtomicU64::new(0);
pub static ACCOUNTING_GUARDS: AtomicU64 = AtomicU64::new(0);
pub static ACCOUNTING_UNGUARDED: AtomicU64 = AtomicU64::new(0);
pub static ACCOUNTING_DISABLED: AtomicU64 = AtomicU64::new(0);
pub static INVENTORY_DIRECTORY_US: AtomicU64 = AtomicU64::new(0);
pub static INVENTORY_ENUM_US: AtomicU64 = AtomicU64::new(0);
pub static INVENTORY_METADATA_US: AtomicU64 = AtomicU64::new(0);
pub static PAGE_WRITES: AtomicU64 = AtomicU64::new(0);
pub static CHECKPOINT_FAST: AtomicU64 = AtomicU64::new(0);
pub static CHECKPOINT_MEDIUM: AtomicU64 = AtomicU64::new(0);
pub static CHECKPOINT_SLOW: AtomicU64 = AtomicU64::new(0);
pub static CHECKPOINT_MAX_US: AtomicU64 = AtomicU64::new(0);
pub static ADMISSION_VALIDATE_US: AtomicU64 = AtomicU64::new(0);
pub static ADMISSION_WAL_US: AtomicU64 = AtomicU64::new(0);
pub static ADMISSION_RESERVE_US: AtomicU64 = AtomicU64::new(0);
pub static INVENTORY_CACHE_US: AtomicU64 = AtomicU64::new(0);
pub static INVENTORY_WALK_US: AtomicU64 = AtomicU64::new(0);
pub static INVENTORY_HITS: AtomicU64 = AtomicU64::new(0);
pub static INVENTORY_WALKS: AtomicU64 = AtomicU64::new(0);
pub static ADMISSION_READS: AtomicU64 = AtomicU64::new(0);
pub static ADMISSION_WRITES: AtomicU64 = AtomicU64::new(0);
pub static SQL_READ_US: AtomicU64 = AtomicU64::new(0);
pub static SQL_WRITE_US: AtomicU64 = AtomicU64::new(0);
pub static COMMIT_US: AtomicU64 = AtomicU64::new(0);
pub static CHECKPOINT_US: AtomicU64 = AtomicU64::new(0);
pub static CHECKPOINTS: AtomicU64 = AtomicU64::new(0);
pub static CAPACITY_CHECKPOINTS: AtomicU64 = AtomicU64::new(0);
pub static MAX_WAL_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn measure<T>(counter: &AtomicU64, work: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = work();
    counter.fetch_add(
        start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    value
}
