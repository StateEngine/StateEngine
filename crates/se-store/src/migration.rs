//! Automatic migration under the sole host's exclusive custody,
//! after a verified backup of the old schema. Readers never migrate.
use crate::{
    connection,
    error::*,
    migration_plan::{STEPS, Step},
    *,
};
use rusqlite::Connection;
use std::time::Duration;
/// Bound on the pre-migration backup; expiry refuses and leaves schema 1.
const BACKUP_BOUND: Duration = Duration::from_secs(300);
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
    for step in STEPS.iter().filter(|step| step.version > from) {
        apply_step(db, step)?;
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
fn apply_step(db: &Connection, step: &Step) -> StoreResult<()> {
    // SQLite's table-rebuild procedure requires enforcement off before BEGIN.
    // The exclusive owner has already backed up the store. Referenced names
    // and rows are restored and checked inside this one schema transaction.
    let Step {
        version,
        sql,
        table_rebuild: rebuild,
    } = step;
    if *rebuild {
        db.execute_batch("PRAGMA foreign_keys=OFF")
            .map_err(sql_error)?;
    }
    let result = (|| {
        db.execute_batch("PRAGMA synchronous=FULL; BEGIN EXCLUSIVE")
            .map_err(sql_error)?;
        db.execute_batch(sql).map_err(sql_error)?;
        if *rebuild {
            let invalid: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
                    [],
                    |r| r.get(0),
                )
                .map_err(sql_error)?;
            if invalid {
                return Err(fail(
                    StoreErrorCode::MigrationFailed,
                    "rebuilt provider tables failed foreign-key readback",
                ));
            }
        }
        db.execute_batch("COMMIT").map_err(sql_error)
    })();
    let rolled_back = result.is_err() && !db.is_autocommit();
    if rolled_back {
        db.execute_batch("ROLLBACK").map_err(sql_error)?;
    }
    if *rebuild {
        db.execute_batch("PRAGMA foreign_keys=ON")
            .map_err(sql_error)?;
        let enabled: bool = db
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .map_err(sql_error)?;
        if !enabled {
            return Err(fail(
                StoreErrorCode::MigrationFailed,
                "foreign-key enforcement was not restored",
            ));
        }
    }
    result.map_err(|e| {
        fail(
            StoreErrorCode::MigrationFailed,
            format!(
                "schema step {version} {}: {}",
                if rolled_back { "rolled back" } else { "failed" },
                e.cause
            ),
        )
    })
}
fn sql_error(e: rusqlite::Error) -> Box<StoreError> {
    sql(e)
}

#[cfg(test)]
mod tests;
