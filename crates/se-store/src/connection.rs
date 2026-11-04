use crate::{error::*, identity, *};
use rusqlite::{Connection, OpenFlags, OptionalExtension, functions::FunctionFlags};
use std::{path::Path, time::Duration};
pub(crate) const APP: u32 = 0x53454e47;
pub(crate) const SCHEMA: u32 = 3;
/// Oldest schema still served: 002 only adds indexes, so the same SQL reads
/// schema 1 correctly while its host migrates it.
pub(crate) const MIN_SCHEMA: u32 = 1;
pub(crate) fn connect(path: &Path, writable: bool, timeout: Duration) -> StoreResult<Connection> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let c = open(
        path,
        flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    configure(&c, path, writable, timeout)?;
    Ok(c)
}
pub(crate) fn open(path: &Path, flags: OpenFlags) -> StoreResult<Connection> {
    Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_EXRESCODE)
        .map_err(|error| sqlite_context(error, path, StoreIoStage::Open))
}
pub(crate) fn begin_snapshot(c: &Connection, path: &Path) -> StoreResult<()> {
    c.execute_batch("BEGIN")
        .map_err(|error| sqlite_context(error, path, StoreIoStage::BeginSnapshot))
}
pub(crate) fn info_at(c: &Connection, path: &Path) -> StoreResult<StoreInfo> {
    info(c).map_err(|error| context(error, path, StoreIoStage::HeaderReadback))
}
pub(crate) fn configure(
    c: &Connection,
    path: &Path,
    writable: bool,
    timeout: Duration,
) -> StoreResult<()> {
    let result = (|| {
        if timeout > Duration::from_secs(5) {
            return Err(invalid("busy timeout exceeds 5000ms"));
        }
        c.busy_timeout(timeout).map_err(sql)?;
        // Nine decoder queries use this bounded cache of SQL programs, never results.
        c.set_prepared_statement_cache_capacity(32);
        c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA mmap_size=0; PRAGMA temp_store=FILE; PRAGMA cache_size=-512;").map_err(sql)?;
        if writable {
            let journal: String = c
                .query_row("PRAGMA journal_mode=WAL", [], |r| {
                    crate::sql_value::value(r, 0)
                })
                .map_err(sql)?;
            if journal != "wal" {
                return Err(fail(StoreErrorCode::PragmaRefused, "WAL refused"));
            }
            c.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=4194304;").map_err(sql)?;
        }
        for (name, arity) in [
            ("se_erase_operation_allowed", 1),
            ("se_erase_body_allowed", 2),
        ] {
            c.create_scalar_function(
                name,
                arity,
                FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(0i64),
            )
            .map_err(sql)?;
        }
        for (name, expected) in [
            ("foreign_keys", 1i64),
            ("trusted_schema", 0),
            ("mmap_size", 0),
            ("temp_store", 1),
        ] {
            let actual: i64 = c
                .query_row(&format!("PRAGMA {name}"), [], |r| {
                    crate::sql_value::value(r, 0)
                })
                .map_err(sql)?;
            if actual != expected {
                return Err(fail(
                    StoreErrorCode::PragmaRefused,
                    format!("{name} readback differs"),
                ));
            }
        }
        Ok(())
    })();
    result.map_err(|error| context(error, path, StoreIoStage::PragmaReadback))
}
pub(crate) fn info(c: &Connection) -> StoreResult<StoreInfo> {
    let app: u32 = c
        .query_row("PRAGMA application_id", [], |r| {
            crate::sql_value::value(r, 0)
        })
        .map_err(sql)?;
    if app != APP {
        return Err(fail(
            StoreErrorCode::ApplicationMismatch,
            "state.db application_id differs",
        ));
    }
    let version: u32 = c
        .query_row("PRAGMA user_version", [], |r| crate::sql_value::value(r, 0))
        .map_err(sql)?;
    if !(MIN_SCHEMA..=SCHEMA).contains(&version) {
        return Err(fail(
            if version > SCHEMA {
                StoreErrorCode::TooNew
            } else {
                StoreErrorCode::VersionUnsupported
            },
            format!("schema {version}; supported schema is {SCHEMA}"),
        ));
    }
    let (id, inc, state): (Vec<u8>, u64, String) = c
        .query_row(
            "SELECT store_id,incarnation,state FROM store_info WHERE singleton=1",
            [],
            |r| {
                Ok((
                    crate::sql_value::value(r, 0)?,
                    crate::sql_value::value(r, 1)?,
                    crate::sql_value::value(r, 2)?,
                ))
            },
        )
        .map_err(sql)?;
    let id = StoreId::from_bytes(id.try_into().map_err(|_| invalid("store_id length"))?)
        .map_err(invalid)?;
    let state = match state.as_str() {
        "ready" => StoreState::Ready,
        "migrating" => StoreState::Migrating,
        "recovering" => StoreState::Recovering,
        "erasing" => StoreState::Erasing,
        _ => return Err(invalid("unknown store state")),
    };
    let last: Option<u64> = c
        .query_row(
            "SELECT seq FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| crate::sql_value::value(r, 0),
        )
        .optional()
        .map_err(sql)?;
    Ok(StoreInfo {
        id: id.clone(),
        incarnation: inc,
        schema_version: version,
        head: last
            .map(|s| StorePosition::new_internal(id, inc, s))
            .transpose()?,
        state,
    })
}
pub(crate) fn validate_lease(
    info: &StoreInfo,
    lease: &dyn RuntimeLease,
    mode: LeaseMode,
) -> StoreResult<LeaseIdentity> {
    let identity = lease.identity()?;
    if identity.store.as_ref() != Some(&info.id)
        || identity.mode != mode
        || identity.generation == 0
        || identity.generation > i64::MAX as u64
    {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "store, mode or generation does not match the held runtime lease",
        ));
    }
    if info.state != StoreState::Ready {
        return Err(fail(
            StoreErrorCode::NotReady,
            "store maintenance is not ready",
        ));
    }
    Ok(identity)
}
pub(crate) fn symbol(c: &Connection, value: &[u8]) -> StoreResult<i64> {
    c.execute(
        "INSERT INTO symbols(value) VALUES(?) ON CONFLICT(value) DO NOTHING",
        [value],
    )
    .map_err(sql)?;
    c.query_row("SELECT id FROM symbols WHERE value=?", [value], |r| {
        crate::sql_value::value(r, 0)
    })
    .map_err(sql)
}
pub(crate) fn payload(c: &Connection, seq: i64, field: &str, text: &str) -> StoreResult<i64> {
    use sha2::{Digest, Sha256};
    c.execute(
        "INSERT INTO payloads(event_seq,field,encoding,content,sha256) VALUES(?,?,'utf8',?,?)",
        crate::sql_value::sql_params![
            seq,
            field,
            text.as_bytes(),
            Sha256::digest(text.as_bytes()).as_slice()
        ],
    )
    .map_err(sql)?;
    Ok(c.last_insert_rowid())
}
pub(crate) fn project_id(c: &Connection, scope: &Scope, insert: bool) -> StoreResult<Vec<u8>> {
    identity::key(
        c,
        "project",
        identity::project(scope)?.as_str(),
        &[0],
        insert,
    )
}
pub(crate) fn now() -> StoreResult<i64> {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(invalid)?;
    i64::try_from(t.as_micros()).map_err(invalid)
}

/// The only two trusted projection names; no caller controls SQL identifiers.
pub(crate) fn mail_table(c: &Connection) -> StoreResult<&'static str> {
    Ok(if info(c)?.schema_version >= 3 {
        "message_deliveries"
    } else {
        "messages"
    })
}
