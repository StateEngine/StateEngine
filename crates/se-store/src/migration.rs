//! Automatic additive migration under the sole host's exclusive custody,
//! after a verified backup of the old schema. Readers never migrate.
use crate::{connection, error::*, *};
use rusqlite::Connection;
use std::time::Duration;
/// Ordered additive steps; each runs only above the store's current version.
const STEPS: [(u32, &str); 3] = [
    (2, include_str!("../migrations/002.sql")),
    (3, include_str!("../migrations/003.sql")),
    (4, include_str!("../migrations/004.sql")),
];
/// Bound on the pre-migration backup; expiry refuses and leaves schema 1.
const BACKUP_BOUND: Duration = Duration::from_secs(300);
/// The DDL a freshly created store applies after 001.
pub(crate) fn fresh() -> impl Iterator<Item = &'static str> {
    STEPS.iter().map(|(_, sql)| *sql)
}
/// Upgrade an older supported schema, or do nothing at the current one.
pub(crate) fn upgrade(
    db: &Connection,
    options: &StoreOptions,
    lease: &dyn RuntimeLease,
    context: BackupContext,
) -> StoreResult<()> {
    let from = connection::info(db)?.schema_version;
    if from >= connection::SCHEMA {
        return Ok(());
    }
    crate::backup::run(options, lease, context, BACKUP_BOUND).map_err(|e| {
        fail(
            StoreErrorCode::MigrationFailed,
            format!(
                "schema {from} kept: first startup may wait up to 300 seconds for its verified pre-migration backup, which failed ({:?}: {})",
                e.code, e.cause
            ),
        )
    })?;
    for (version, sql) in STEPS.iter().filter(|(v, _)| *v > from) {
        db.execute_batch("PRAGMA synchronous=FULL; BEGIN EXCLUSIVE")
            .map_err(sql_error)?;
        if let Err(e) = db.execute_batch(sql) {
            let _ = db.execute_batch("ROLLBACK");
            return Err(fail(
                StoreErrorCode::MigrationFailed,
                format!("schema step {version} rolled back: {e}"),
            ));
        }
        db.execute_batch("COMMIT").map_err(sql_error)?;
    }
    let after = connection::info(db)?.schema_version;
    db.execute_batch("PRAGMA synchronous=NORMAL")
        .map_err(sql_error)?;
    let synchronous: i64 = db
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .map_err(sql_error)?;
    if after != connection::SCHEMA || synchronous != 1 {
        return Err(fail(
            StoreErrorCode::MigrationFailed,
            format!("schema {after} / synchronous {synchronous} readback after migration"),
        ));
    }
    Ok(())
}
fn sql_error(e: rusqlite::Error) -> Box<StoreError> {
    sql(e)
}
