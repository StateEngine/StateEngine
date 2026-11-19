//! Diagnostic timing for the private cold writer.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub static ADMISSION_US: AtomicU64 = AtomicU64::new(0);
pub static SQL_READ_US: AtomicU64 = AtomicU64::new(0);
pub static SQL_WRITE_US: AtomicU64 = AtomicU64::new(0);
pub static COMMIT_US: AtomicU64 = AtomicU64::new(0);
pub static CHECKPOINT_US: AtomicU64 = AtomicU64::new(0);

pub fn measure<T>(counter: &AtomicU64, work: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = work();
    counter.fetch_add(
        start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    value
}
