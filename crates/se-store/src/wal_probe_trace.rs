//! Temporary probe instrumentation shared by both experimental arms.
use crate::{StoreResult, connection, error::*, transaction::checkpoint::probe};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Write,
    sync::{Mutex, OnceLock},
    time::Instant,
};

pub(crate) fn record(value: Value) -> StoreResult<()> {
    static OUTPUT: OnceLock<Result<Option<Mutex<File>>, String>> = OnceLock::new();
    let output = OUTPUT.get_or_init(|| {
        std::env::var_os("SE_WAL_PROBE_TRACE")
            .map(|path| {
                File::create(path)
                    .map(Mutex::new)
                    .map_err(|e| e.to_string())
            })
            .transpose()
    });
    let Some(output) = output.as_ref().map_err(invalid)? else {
        return Ok(());
    };
    let mut file = output.lock().map_err(invalid)?;
    serde_json::to_writer(&mut *file, &value).map_err(invalid)?;
    file.write_all(b"\n").map_err(invalid)?;
    file.flush().map_err(invalid)?;
    Ok(())
}

pub(crate) fn checkpoint(
    db: &Connection,
    mode: &str,
    location: &str,
) -> StoreResult<(i64, i64, i64)> {
    let before = probe(db)?;
    let start = Instant::now();
    let result = db
        .query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(sql);
    let elapsed = start.elapsed().as_micros();
    let after = probe(db);
    record(
        json!({"kind":"checkpoint", "location":location,"mode":mode,"elapsed_us":elapsed,
        "before_log":before.log,"before_done":before.done,"before_bytes":before.bytes,
        "result":result.as_ref().ok(),"error":result.as_ref().err().map(|e|e.to_string()),
        "after_log":after.as_ref().ok().map(|w|w.log),"after_done":after.as_ref().ok().map(|w|w.done),
        "lease_header_readable":connection::lease_state(db).is_ok()}),
    )?;
    result
}
