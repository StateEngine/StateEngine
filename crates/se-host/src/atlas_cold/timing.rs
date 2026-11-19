//! Cold-path diagnostic wall-clock counters, in microseconds.
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) static SOURCE: AtomicU64 = AtomicU64::new(0);
pub(super) static PARSE: AtomicU64 = AtomicU64::new(0);
pub(super) static RESOLVE: AtomicU64 = AtomicU64::new(0);
pub(super) static VERIFY: AtomicU64 = AtomicU64::new(0);
pub(super) static FILE: AtomicU64 = AtomicU64::new(0);
pub(super) static CHECKPOINT: AtomicU64 = AtomicU64::new(0);
pub(super) static RELEASE: AtomicU64 = AtomicU64::new(0);
pub(super) static FINAL_SYNC: AtomicU64 = AtomicU64::new(0);
pub(super) static FINAL_FLUSH: AtomicU64 = AtomicU64::new(0);

pub(super) fn totals(elapsed_ms: u128, files: u64) -> String {
    use se_atlas::cache::timing as sql;
    let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    format!(
        "elapsed_ms={elapsed_ms} files={files} source_us={} parse_us={} resolve_us={} verify_us={} file_us={} checkpoint_us={} release_us={} admission_us={} sql_read_us={} sql_write_us={} commit_us={} sqlite_checkpoint_us={} checkpoints={} capacity_checkpoints={} max_wal_bytes={} final_sync_us={} final_flush_us={} admission_validate_us={} admission_wal_us={} admission_reserve_us={} inventory_cache_us={} inventory_walk_us={} inventory_hits={} inventory_walks={} admission_reads={} admission_writes={} private_guard={} inventory_directory_us={} inventory_enum_us={} inventory_metadata_us={} page_writes={} checkpoint_fast={} checkpoint_medium={} checkpoint_slow={} checkpoint_max_us={}",
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
        read(&sql::CHECKPOINT_US),
        read(&sql::CHECKPOINTS),
        read(&sql::CAPACITY_CHECKPOINTS),
        read(&sql::MAX_WAL_BYTES),
        read(&FINAL_SYNC),
        read(&FINAL_FLUSH),
        read(&sql::ADMISSION_VALIDATE_US),
        read(&sql::ADMISSION_WAL_US),
        read(&sql::ADMISSION_RESERVE_US),
        read(&sql::INVENTORY_CACHE_US),
        read(&sql::INVENTORY_WALK_US),
        read(&sql::INVENTORY_HITS),
        read(&sql::INVENTORY_WALKS),
        read(&sql::ADMISSION_READS),
        read(&sql::ADMISSION_WRITES),
        read(&sql::PRIVATE_GUARD),
        read(&sql::INVENTORY_DIRECTORY_US),
        read(&sql::INVENTORY_ENUM_US),
        read(&sql::INVENTORY_METADATA_US),
        read(&sql::PAGE_WRITES),
        read(&sql::CHECKPOINT_FAST),
        read(&sql::CHECKPOINT_MEDIUM),
        read(&sql::CHECKPOINT_SLOW),
        read(&sql::CHECKPOINT_MAX_US)
    )
}
