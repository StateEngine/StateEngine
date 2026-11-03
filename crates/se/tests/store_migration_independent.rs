//! Public native host migration consumer; no private migration implementation.
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use se_host::{HostedRuntime, initialize_host_process};
use se_store::*;
use std::fs;
use support::*;

fn schema_one(f: &Fixture, obstruct: bool) -> Check {
    seed(f)?;
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    for name in [
        "cursor_data_cursor",
        "process_data_principal",
        "effect_offer_attempt",
        "sessions_cleanup",
        "process_data_session",
    ] {
        if !(obstruct && name == "cursor_data_cursor") {
            db.execute_batch(&format!("DROP INDEX {name}"))?;
        }
    }
    db.execute_batch("PRAGMA user_version=1")?;
    Ok(())
}
fn backup_is_original(f: &Fixture, expected_head: u64) -> Check {
    // Backup inventory is a named, unsupported API on this base. Read the
    // public on-disk manifest and independently hash/open its exact old copy.
    let root = f.options.state_directory.join("backups");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("backup-index.json"))?)?;
    let backup = manifest["generations"]
        .as_array()
        .ok_or("backup generations absent")?
        .iter()
        .find(|entry| entry["schema"] == 1 && entry["validated"] == true)
        .ok_or("verified pre-migration schema-1 backup absent")?;
    assert_eq!(backup["through"].as_u64(), Some(expected_head));
    let name = backup["file"].as_str().ok_or("backup filename absent")?;
    assert!(
        name.starts_with("state-backup-")
            && name.ends_with(".db")
            && !name.contains('/')
            && !name.contains('\\')
    );
    let path = root.join(name);
    let bytes = fs::read(&path)?;
    use sha2::{Digest, Sha256};
    assert_eq!(Some(bytes.len() as u64), backup["bytes"].as_u64());
    assert_eq!(
        serde_json::to_value(<[u8; 32]>::from(Sha256::digest(&bytes)))?,
        backup["sha256"]
    );
    let db =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?,
        1
    );
    assert_eq!(
        db.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
        "ok"
    );
    Ok(())
}
fn check(obstruct: bool) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    schema_one(&f, obstruct)?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let before = reader.info()?;
    let before_sequence: i64 = rusqlite::Connection::open_with_flags(
        f.options.state_directory.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?
    .query_row("SELECT MAX(seq) FROM events", [], |row| row.get(0))?;
    assert_eq!(
        before.schema_version, 1,
        "a read-only open must not migrate"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    let outcome = rt.block_on(async {
        let prepared =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await;
        if obstruct {
            return match prepared {
                Err(error) => {
                    assert!(
                        error.to_string().contains("rolled back"),
                        "wrong migration refusal: {error}"
                    );
                    Ok(())
                }
                Ok(_) => Err(
                    "partially indexed schema-1 store incorrectly escaped as a prepared host"
                        .into(),
                ),
            };
        }
        let mut host = prepared?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        host.local_stop().request();
        let report = host.serve(listener).await.finish(&bound()?).await;
        assert!(
            report.transport_closed && report.endpoint_retired,
            "native fixture endpoint did not close"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    outcome?;
    let after = reader.info()?;
    assert_eq!(after.schema_version, if obstruct { 1 } else { 2 });
    assert_eq!(after.id, before.id);
    // Startup may append runtime ownership; the backup must bind the old head.
    backup_is_original(&f, u64::try_from(before_sequence)?)?;
    let db = rusqlite::Connection::open_with_flags(
        f.options.state_directory.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let added: u32 = db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name IN ('cursor_data_cursor','process_data_principal','effect_offer_attempt','sessions_cleanup','process_data_session')", [], |row| row.get(0))?;
    assert_eq!(
        added,
        if obstruct { 1 } else { 5 },
        "DDL was only partly committed"
    );
    Ok(())
}
#[test]
fn native_host_upgrades_schema_one_only_after_verified_original_backup() -> Check {
    check(false)
}
#[test]
fn refused_ddl_keeps_schema_one_and_verified_backup_without_partial_indexes() -> Check {
    check(true)
}
