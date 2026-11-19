//! Cold-path diagnostic wall-clock counters, in microseconds.
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) static SOURCE: AtomicU64 = AtomicU64::new(0);
pub(super) static PARSE: AtomicU64 = AtomicU64::new(0);
pub(super) static RESOLVE: AtomicU64 = AtomicU64::new(0);
pub(super) static VERIFY: AtomicU64 = AtomicU64::new(0);
pub(super) static FILE: AtomicU64 = AtomicU64::new(0);
pub(super) static CHECKPOINT: AtomicU64 = AtomicU64::new(0);
pub(super) static RELEASE: AtomicU64 = AtomicU64::new(0);

pub(super) fn totals(elapsed_ms: u128, files: u64) -> String {
    use se_atlas::cache::timing as sql;
    let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    format!(
        "elapsed_ms={elapsed_ms} files={files} source_us={} parse_us={} resolve_us={} verify_us={} file_us={} checkpoint_us={} release_us={} admission_us={} sql_read_us={} sql_write_us={} commit_us={} sqlite_checkpoint_us={}",
        read(&SOURCE),
        read(&PARSE),
        read(&RESOLVE),
        read(&VERIFY),
        read(&FILE),
        read(&CHECKPOINT),
        read(&RELEASE),
        read(&sql::ADMISSION_US),
        read(&sql::SQL_READ_US),
        read(&sql::SQL_WRITE_US),
        read(&sql::COMMIT_US),
        read(&sql::CHECKPOINT_US)
    )
}
