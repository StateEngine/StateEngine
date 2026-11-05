//! Search commits immediately; the change feed crosses one publication fence.
use super::*;
use crate::{
    cache::connection::SqlView,
    errors::{AtlasResult, cache_error},
    model::*,
};
use rusqlite::params;
use se_types::code::AtlasText;
#[derive(serde::Serialize, serde::Deserialize)]
struct Summary {
    reason: BulkReason,
    semantic: u64,
    complete: bool,
}
/// Called on a source event, never from a query. Checkout/HEAD observation can
/// promote an already provisional event batch without publishing earlier rows.
pub fn begin(
    sql: &SqlView<'_>,
    serial: u64,
    reason: BulkReason,
    force_bulk: bool,
) -> AtlasResult<()> {
    execute(
        sql,
        "INSERT OR IGNORE INTO active_batch VALUES(1,?1,?2,?2,0,?3,?4)",
        params![
            format!("{reason:?}"),
            n(serial),
            force_bulk,
            json(&Summary {
                reason,
                semantic: 0,
                complete: true
            })?
        ],
    )?;
    execute(
        sql,
        "UPDATE active_batch SET last_serial=max(last_serial,?1) WHERE singleton=1",
        [n(serial)],
    )?;
    if force_bulk {
        let mut summary: Summary = serde_json::from_str(&value::<String, _>(
            sql,
            "SELECT summary_json FROM active_batch WHERE singleton=1",
            [],
        )?)
        .map_err(cache_error)?;
        summary.reason = reason;
        execute(
            sql,
            "UPDATE active_batch SET bulk=1,kind=?1,summary_json=?2 WHERE singleton=1",
            params![format!("{reason:?}"), json(&summary)?],
        )?;
        execute(sql, "DELETE FROM staged_changes", [])?;
    }
    Ok(())
}
pub fn observe_file(sql: &SqlView<'_>, file: FileId, path: &RelativePath) -> AtlasResult<()> {
    execute(
        sql,
        "INSERT OR IGNORE INTO batch_files(file_key,path) VALUES(?1,?2)",
        params![file.0.as_slice(), path.as_str()],
    )?;
    let count: u64 = unsigned(sql, "SELECT count(*) FROM batch_files", [])?;
    execute(
        sql,
        "UPDATE active_batch SET distinct_files=?1,bulk=max(bulk,?2) WHERE singleton=1",
        params![n(count), count > 100],
    )?;
    if count > 100 {
        execute(sql, "DELETE FROM staged_changes", [])?;
    }
    Ok(())
}
pub fn stage(sql: &SqlView<'_>, fact: diff::Fact) -> AtlasResult<()> {
    if value::<u32, _>(sql, "SELECT count(*) FROM active_batch", [])? != 1 {
        return Err(cache_error("change fact has no active source batch"));
    }
    let mut summary: Summary = serde_json::from_str(&value::<String, _>(
        sql,
        "SELECT summary_json FROM active_batch WHERE singleton=1",
        [],
    )?)
    .map_err(cache_error)?;
    summary.semantic = summary.semantic.saturating_add(1);
    execute(
        sql,
        "UPDATE active_batch SET summary_json=?1 WHERE singleton=1",
        [json(&summary)?],
    )?;
    if value::<bool, _>(sql, "SELECT bulk FROM active_batch WHERE singleton=1", [])? {
        return Ok(());
    }
    let payload = json(&fact)?;
    let (rows,bytes):(u64,u64)=sql.prepare("SELECT count(*),coalesce(sum(length(CAST(payload_json AS BLOB))),0) FROM staged_changes")?.query_row([],|r|Ok((column(r,0)?,column(r,1)?))).map_err(cache_error)?;
    if rows >= 50_000 || bytes + payload.len() as u64 > 8_000_000 {
        execute(sql, "UPDATE active_batch SET bulk=1 WHERE singleton=1", [])?;
        execute(sql, "DELETE FROM staged_changes", [])?;
    } else {
        execute(
            sql,
            "INSERT INTO staged_changes VALUES(?1,?2,?3)",
            params![n(rows), fact.file.0.as_slice(), payload],
        )?;
    }
    Ok(())
}
/// Discovery/event serial must already be fenced by the controller. An
/// interrupted/recovered batch publishes one explicitly incomplete summary.
pub fn publish(
    sql: &SqlView<'_>,
    observed_unix_ms: i64,
    interrupted: bool,
) -> AtlasResult<Option<Generation>> {
    if value::<u32, _>(sql, "SELECT count(*) FROM active_batch", [])? == 0 {
        return Ok(None);
    }
    let (serial,files,bulk,summary):(u64,u64,bool,String)=sql.prepare("SELECT last_serial,distinct_files,bulk,summary_json FROM active_batch WHERE singleton=1")?.query_row([],|r|Ok((column(r,0)?,column(r,1)?,r.get(2)?,r.get(3)?))).map_err(cache_error)?;
    let summary: Summary = serde_json::from_str(&summary).map_err(cache_error)?;
    let generation: u64 = unsigned(
        sql,
        "SELECT index_generation+1 FROM meta WHERE singleton=1",
        [],
    )?;
    execute(
        sql,
        "INSERT INTO generations VALUES(?1,?2,?3,?4)",
        params![
            n(generation),
            observed_unix_ms,
            n(serial),
            if bulk || interrupted { "Bulk" } else { "Files" }
        ],
    )?;
    if bulk || interrupted {
        let mut paths = sql.prepare("SELECT path FROM batch_files ORDER BY path LIMIT 5")?;
        let samples = paths
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(cache_error)?
            .map(|r| RelativePath::new(r.map_err(cache_error)?))
            .collect::<AtlasResult<Vec<_>>>()?;
        let bulk = BulkChange {
            id: ChangeId {
                generation: Generation(generation),
                ordinal: 0,
            },
            reason: summary.reason,
            files,
            semantic_changes: Some(summary.semantic),
            sample_paths: samples,
            complete: summary.complete && !interrupted,
        };
        execute(
            sql,
            "INSERT INTO changes(generation,ordinal,kind,baseline_reset,bulk_json) VALUES(?1,0,'Bulk',0,?2)",
            params![n(generation), json(&bulk)?],
        )?;
    } else {
        let mut statement =
            sql.prepare("SELECT ordinal,payload_json FROM staged_changes ORDER BY ordinal")?;
        let mut rows = statement.query([]).map_err(cache_error)?;
        while let Some(row) = rows.next().map_err(cache_error)? {
            let ordinal: u32 = row.get(0).map_err(cache_error)?;
            let fact: diff::Fact =
                serde_json::from_str(&row.get::<_, String>(1).map_err(cache_error)?)
                    .map_err(cache_error)?;
            let pointer = CodePointer {
                file: fact.file,
                path: fact.path.clone(),
                span: fact.span,
                content_hash: if fact.kind == ChangeKind::Removed {
                    fact.previous
                } else {
                    fact.current
                },
                freshness: SnapshotFreshness::Current,
            };
            execute(
                sql,
                "INSERT INTO changes(generation,ordinal,file_key,symbol_key,path,kind,pointer_json,previous_hash,current_hash,dependent_count,dependent_complete,dependent_generation,baseline_reset) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,0,?1,?10)",
                params![
                    n(generation),
                    ordinal,
                    fact.file.0.as_slice(),
                    fact.symbol.as_ref().map(|s| s.0.as_slice()),
                    fact.path.as_str(),
                    format!("{:?}", fact.kind),
                    json(&pointer)?,
                    fact.previous.as_ref().map(|s| s.0.as_slice()),
                    fact.current.as_ref().map(|s| s.0.as_slice()),
                    fact.baseline_reset
                ],
            )?;
        }
    }
    execute(
        sql,
        "UPDATE meta SET index_generation=?1,published_generation=?1 WHERE singleton=1",
        [n(generation)],
    )?;
    execute(
        sql,
        "UPDATE files SET last_code_generation=?1 WHERE key IN (SELECT file_key FROM batch_files)",
        [n(generation)],
    )?;
    execute(sql, "DELETE FROM staged_changes", [])?;
    execute(sql, "DELETE FROM batch_files", [])?;
    execute(sql, "DELETE FROM active_batch", [])?;
    Ok(Some(Generation(generation)))
}
