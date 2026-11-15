use crate::{Result, measure, until};
use se_atlas::{
    cache::{connection::*, pointer, *},
    model::*,
    scope::Scope,
};
use se_host::atlas_cache::NativeAtlasCache;
use serde_json::{Value, json};
use std::{
    ffi::c_int,
    path::Path,
    sync::atomic::{AtomicPtr, Ordering},
};
static LAST: AtomicPtr<rusqlite::ffi::sqlite3> = AtomicPtr::new(std::ptr::null_mut());
unsafe extern "C" fn opened(
    db: *mut rusqlite::ffi::sqlite3,
    _: *mut *mut libc::c_char,
    _: *const rusqlite::ffi::sqlite3_api_routines,
) -> c_int {
    LAST.store(db, Ordering::Release);
    rusqlite::ffi::SQLITE_OK
}
fn sql_memory(reset: bool) -> Result<(i64, i64)> {
    let (mut current, mut peak) = (0, 0);
    let code = unsafe {
        rusqlite::ffi::sqlite3_status64(
            rusqlite::ffi::SQLITE_STATUS_MEMORY_USED,
            &mut current,
            &mut peak,
            i32::from(reset),
        )
    };
    if code != 0 {
        return Err(format!("native SQLite memory counter failed: {code}").into());
    }
    Ok((current, peak))
}
fn connection_memory(db: *mut rusqlite::ffi::sqlite3) -> Result<Value> {
    if db.is_null() {
        return Err("native SQL handle absent".into());
    }
    let mut counters = serde_json::Map::new();
    for (name, operation) in [
        ("cache", rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED),
        ("schema", rusqlite::ffi::SQLITE_DBSTATUS_SCHEMA_USED),
        ("statements", rusqlite::ffi::SQLITE_DBSTATUS_STMT_USED),
    ] {
        let (mut current, mut peak) = (0, 0);
        let code =
            unsafe { rusqlite::ffi::sqlite3_db_status(db, operation, &mut current, &mut peak, 0) };
        if code != 0 {
            return Err(format!("native SQL counter failed: {code}").into());
        }
        counters.insert(name.into(), json!(current));
    }
    Ok(Value::Object(counters))
}
fn error(value: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("native SQL admission measurement", &value.to_string())
}
fn scan(connection: &mut CacheConnection<'_>, ordered: bool) -> Result<u64> {
    Ok(connection.read(until(), |sql| {
        let mut statement = sql.prepare(if ordered {
            "SELECT text FROM names ORDER BY length(text),text"
        } else {
            "SELECT text FROM names ORDER BY id"
        })?;
        let mut rows = statement.query([]).map_err(error)?;
        let mut bytes = 0;
        while let Some(row) = rows.next().map_err(error)? {
            bytes += row
                .get_ref(0)
                .map_err(error)?
                .as_str()
                .map_err(error)?
                .len() as u64;
        }
        Ok(bytes)
    })?)
}
fn sample(label: &str, handles: &[*mut rusqlite::ffi::sqlite3]) -> Result<Value> {
    let (current, peak) = sql_memory(false)?;
    Ok(
        json!({"phase":label,"sqlite_current":current,"sqlite_high_water":peak,
        "handles":handles.iter().map(|handle| connection_memory(*handle)).collect::<Result<Vec<_>>>()?,
        "zone":measure::zone(),"physical_peak":se_proc::atlas_worker::memory_usage()?}),
    )
}
pub fn run(scope: Scope, root: &Path) -> Result<Value> {
    let code = unsafe { rusqlite::ffi::sqlite3_auto_extension(Some(opened)) };
    if code != 0 {
        return Err(format!("native SQL handle observer refused: {code}").into());
    }
    let cache = NativeAtlasCache::create(&root.join("cache"), scope.clone())?;
    let coverage = serde_json::from_value(
        json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope,
            epoch: CacheEpoch::from_parts(1, [9; 10])?,
        },
        extractor_version: "native-admission-control".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::Current,
    };
    let mut cold = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        until(),
    )?;
    for batch in 0..8 {
        cold.write(1_000_000, until(), |sql| {
            let mut statement = sql.prepare("INSERT INTO names(text) VALUES(?1)")?;
            for row in 0..512 {
                statement
                    .execute([format!("entry_{batch}_{row}_{}", "x".repeat(180))])
                    .map_err(error)?;
            }
            Ok(())
        })?;
    }
    pointer::publish(&cache, &mut cold, None, until())?;
    drop(cold);
    // Arithmetic-only allowance to open the measured path. It grants no admission.
    let provisional = SqlProfile::from_qualified_overhead((SQL_QUERY_BYTES - 262_144) / 2)?;
    sql_memory(true)?;
    let mut observations = vec![sample("before-host-open", &[])?];
    for round in 0..12 {
        let mut writer = CacheConnection::open(
            &cache,
            seed.identity.clone(),
            ConnectionRole::HostWriter,
            &provisional,
            until(),
        )?
        .ok_or("writer absent")?;
        let writer_handle = LAST.load(Ordering::Acquire);
        let mut reader = CacheConnection::open(
            &cache,
            seed.identity.clone(),
            ConnectionRole::HostReader,
            &provisional,
            until(),
        )?
        .ok_or("reader absent")?;
        let reader_handle = LAST.load(Ordering::Acquire);
        observations.push(sample(
            &format!("{round}-both-open"),
            &[writer_handle, reader_handle],
        )?);
        let bytes = scan(&mut writer, false)? + scan(&mut reader, true)?;
        if bytes < 1_000_000 {
            return Err("SQL fixture did not fill both native caches".into());
        }
        observations.push(sample(
            &format!("{round}-both-scanned"),
            &[writer_handle, reader_handle],
        )?);
        // Hold the maximum admitted statement count while observing real handles.
        writer.read(until(), |sql| {
            let mut statements = Vec::new();
            let mut refused = None;
            for _ in 0..9 {
                match sql.prepare("SELECT text FROM names WHERE id=?1") {
                    Ok(statement) => statements.push(statement),
                    Err(error) => {
                        if !matches!(error.body.detail(), se_types::Detail::AtlasResourceBudget(_)) { return Err(error); }
                        refused = Some(serde_json::to_value(&error.body).map_err(crate::sql::error)?);
                        break;
                    },
                }
            }
            if statements.is_empty() {
                return Err(error("no statement admitted"));
            }
            observations.push(json!({"phase":format!("{round}-statement-admission"),"held":statements.len(),"refusal":refused}));
            observations.push(
                sample(
                    &format!("{round}-statements-held"),
                    &[writer_handle, reader_handle],
                )
                .map_err(error)?,
            );
            Ok(())
        })?;
        drop(reader);
        drop(writer);
        observations.push(sample(&format!("{round}-all-closed"), &[])?);
    }
    Ok(
        json!({"provisional_only":true,"sql_total_reservation":SQL_QUERY_BYTES,"fixed_cache_statement_arena_reservation":262_144,"rows":observations,
        "limitations":["Native bounded adapter inputs; no universal SQL plan or whole-host bound","Allocator reserved/touched memory retained separately from SQLite counters","No allocator configuration, SQL guard or production pragma changed"]}),
    )
}
