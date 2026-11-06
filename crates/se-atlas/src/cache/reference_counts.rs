//! Popularity is a graph projection, never a synthetic touch. Call within the
//! same finite write transaction as the corresponding reference mutation.
use super::connection::SqlView;
use crate::errors::{AtlasResult, cache_error};
use rusqlite::params;

/// Apply a complete file's installed reference set after insertion. Grouped
/// targets avoid preparing two updates per occurrence of a popular identifier.
pub(crate) fn installed(sql: &SqlView<'_>, file: i64) -> AtlasResult<()> {
    adjust(sql, file, 1)
}
/// Remove outgoing authority before deleting/replacing a file's references or
/// marking them NameOnly. Stream one target/count pair, not a graph inventory.
pub(crate) fn outgoing(sql: &SqlView<'_>, file: i64) -> AtlasResult<()> {
    adjust(sql, file, -1)
}
fn adjust(sql: &SqlView<'_>, file: i64, direction: i64) -> AtlasResult<()> {
    let mut statement = sql.prepare("SELECT s.key,f.key,count(*) FROM refs r JOIN symbols s ON s.id=r.target JOIN files f ON f.id=s.file WHERE r.file=?1 AND r.accuracy!='NameOnly' GROUP BY f.key,s.key")?;
    let mut rows = statement.query([file]).map_err(cache_error)?;
    let mut current: Option<(Vec<u8>, i64)> = None;
    while let Some(row) = rows.next().map_err(cache_error)? {
        let target: Vec<u8> = row.get(0).map_err(cache_error)?;
        let target_file: Vec<u8> = row.get(1).map_err(cache_error)?;
        let count: i64 = row.get::<_, i64>(2).map_err(cache_error)? * direction;
        if current
            .as_ref()
            .is_some_and(|(prior, _)| prior != &target_file)
        {
            let (prior, total) = current
                .take()
                .ok_or_else(|| cache_error("file counter cursor disappeared"))?;
            delta(sql, "file", &prior, total)?;
        }
        let total = current
            .as_ref()
            .map_or(0, |(_, total)| *total)
            .checked_add(count)
            .ok_or_else(|| cache_error("file reference count overflow"))?;
        current = Some((target_file, total));
        delta(sql, "symbol", &target, count)?;
    }
    if let Some((file, total)) = current {
        delta(sql, "file", &file, total)?;
    }
    Ok(())
}
fn delta(sql: &SqlView<'_>, kind: &str, key: &[u8], count: i64) -> AtlasResult<()> {
    if count > 0 {
        sql.prepare("INSERT OR IGNORE INTO activity(target_kind,target_key,last_touch_unix_ms,inbound_resolved) VALUES(?1,?2,NULL,0)")?
            .execute(params![kind,key]).map_err(cache_error)?;
    }
    if sql.prepare("UPDATE activity SET inbound_resolved=inbound_resolved+?3 WHERE target_kind=?1 AND target_key=?2")?
        .execute(params![kind,key,count]).map_err(cache_error)? != 1 {
        return Err(cache_error("reference count target disappeared"));
    }
    Ok(())
}
/// All incoming authority for the target file is about to be invalidated. The
/// file counter is already the sum of these symbol counters, so no edge scan
/// or second retained graph is necessary to reset both projections.
pub(crate) fn incoming(sql: &SqlView<'_>, file: i64) -> AtlasResult<()> {
    for statement in [
        "UPDATE activity SET inbound_resolved=0 WHERE target_kind='file' AND target_key=(SELECT key FROM files WHERE id=?1)",
        "UPDATE activity SET inbound_resolved=0 WHERE target_kind='symbol' AND target_key IN(SELECT key FROM symbols WHERE file=?1)",
        "DELETE FROM activity WHERE target_kind='symbol' AND last_touch_unix_ms IS NULL AND inbound_resolved=0 AND target_key IN(SELECT key FROM symbols WHERE file=?1)",
    ] {
        sql.prepare(statement)?
            .execute([file])
            .map_err(cache_error)?;
    }
    Ok(())
}
