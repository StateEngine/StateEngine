//! Bounded maintenance on actual cache activity; no timer or authoritative deletes.
use super::connection::{CacheConnection, SqlView};
use crate::errors::{AtlasResult, cache_error, capacity};
use std::time::Instant;
#[derive(Clone, Copy, Debug)]
pub struct PruneReport {
    pub deleted: u32,
    pub retention_floor: u64,
    pub pending: bool,
}
/// Work is bounded per SQL delete. A raised floor makes the whole retired
/// generation unavailable immediately, while its physical rows drain in quanta.
/// The 30-observed-day limit applies even after a quiet month: it may retire the
/// newest published generation and all old changes. That is an expired baseline,
/// never a checked empty changes range. Unpublished staging is not aged here.
pub fn changes(
    db: &CacheConnection<'_>,
    observed_unix_ms: i64,
    rows: u32,
    deadline: Instant,
) -> AtlasResult<PruneReport> {
    if !(1..=1024).contains(&rows) {
        return Err(se_types::SeError::invalid(
            "Atlas prune batch",
            "1..1024 rows",
        ));
    }
    let cutoff = observed_unix_ms.saturating_sub(30 * 24 * 60 * 60 * 1000);
    db.write(1_000_000,deadline,|sql| {
        let current:i64=query(sql,"SELECT retention_floor FROM meta WHERE singleton=1",[])?;
        let aged:Option<i64>=query(sql,"SELECT max(generation) FROM generations
            WHERE observed_unix_ms<?1
              AND generation<=(SELECT published_generation FROM meta WHERE singleton=1)",[cutoff])?;
        let excess:Option<i64>=query(sql,"SELECT max(generation) FROM (SELECT generation FROM changes ORDER BY generation DESC,ordinal DESC LIMIT 1 OFFSET 50000)",[])?;
        let floor=current.max(aged.unwrap_or(0)).max(excess.unwrap_or(0));
        if floor<0 {return Err(cache_error("negative retention floor"))}
        execute(sql,"UPDATE meta SET retention_floor=?1 WHERE singleton=1",[floor])?;
        let deleted=execute(sql,"DELETE FROM changes WHERE (generation,ordinal) IN (
            SELECT generation,ordinal FROM changes WHERE generation<=?1
            ORDER BY generation,ordinal LIMIT ?2)",rusqlite::params![floor,rows])?;
        let pending:i64=query(sql,"SELECT EXISTS(SELECT 1 FROM changes WHERE generation<=?1)",[floor])?;
        Ok(PruneReport {deleted:deleted as u32,retention_floor:floor as u64,pending:pending!=0})
    })
}
/// Each fixed cleanup has a bounded row batch. A caller repeats on its next
/// admitted quantum while pending; it never declares Current with garbage queued.
pub fn metadata(db: &CacheConnection<'_>, rows: u32, deadline: Instant) -> AtlasResult<bool> {
    if !(1..=1024).contains(&rows) {
        return Err(se_types::SeError::invalid(
            "Atlas prune batch",
            "1..1024 rows",
        ));
    }
    db.write(1_000_000, deadline, |sql| {
        let mut pending = false;
        for statement in [
            "DELETE FROM names WHERE id IN (
                SELECT id FROM names n
                WHERE NOT EXISTS(SELECT 1 FROM symbols WHERE name=n.id)
                  AND NOT EXISTS(SELECT 1 FROM refs WHERE spelling=n.id)
                  AND NOT EXISTS(SELECT 1 FROM imports WHERE local_name=n.id OR imported_name=n.id)
                LIMIT ?1)",
            "DELETE FROM observed_commits WHERE (oid,generation) IN (
                SELECT oid,generation FROM observed_commits
                ORDER BY generation DESC,oid LIMIT ?1 OFFSET 256)",
            "DELETE FROM generations WHERE generation IN (
                SELECT generation FROM generations g
                WHERE NOT EXISTS(SELECT 1 FROM changes WHERE generation=g.generation)
                  AND NOT EXISTS(SELECT 1 FROM observed_commits WHERE generation=g.generation)
                  AND generation<=(SELECT retention_floor FROM meta WHERE singleton=1)
                LIMIT ?1)",
            "DELETE FROM touches WHERE (target_kind,target_key,ordinal) IN (
                SELECT t.target_kind,t.target_key,t.ordinal FROM touches t
                WHERE (SELECT count(*) FROM touches newer
                       WHERE newer.target_kind=t.target_kind AND newer.target_key=t.target_key
                         AND newer.ordinal>t.ordinal)>=10 LIMIT ?1)",
        ] {
            pending |= execute(sql, statement, [rows])? == rows as usize;
        }
        Ok(pending)
    })
}
/// Keep referenced commit anchors and prune the oldest unreferenced excess.
/// Incoming record/commit mentions are the references; outgoing changed paths
/// disappear with the pruned commit rather than pinning every commit forever.
pub fn commits(db: &CacheConnection<'_>, rows: u32, deadline: Instant) -> AtlasResult<bool> {
    if !(1..=1024).contains(&rows) {
        return Err(se_types::SeError::invalid(
            "Atlas prune batch",
            "1..1024 rows",
        ));
    }
    db.write(1_000_000, deadline, |sql| {
        let excess: i64 = query(sql, "SELECT max(count(*)-20000,0) FROM commits", [])?;
        let limit = excess.min(i64::from(rows));
        if limit == 0 {
            return Ok(false);
        }
        let mut select = sql.prepare(
            "SELECT id FROM commits c
            WHERE NOT EXISTS(SELECT 1 FROM mentions WHERE target_kind='commit' AND target_key=c.oid)
            ORDER BY author_unix_ms,id LIMIT ?1",
        )?;
        let ids = select
            .query_map([limit], |r| r.get::<_, i64>(0))
            .map_err(cache_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cache_error)?;
        drop(select);
        if ids.is_empty() {
            return Err(capacity(
                "Atlas referenced commit retention",
                excess as u64,
                0,
            ));
        }
        for id in &ids {
            // A producer quantum admits at most 32 changed files per commit.
            // Hold only those keys before the FK cascade removes their seeds.
            let mut statement = sql.prepare(
                "SELECT target_key FROM touches
                 WHERE source_commit=?1 AND target_kind='file' LIMIT 33",
            )?;
            let keys = statement
                .query_map([id], |r| r.get::<_, Vec<u8>>(0))
                .map_err(cache_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(cache_error)?;
            drop(statement);
            if keys.len() > 32 {
                return Err(capacity(
                    "Git commit file-seed retirement",
                    keys.len() as u64,
                    32,
                ));
            }
            execute(
                sql,
                "DELETE FROM mentions WHERE source_kind='commit' AND source_id=?1",
                [*id],
            )?;
            execute(sql, "DELETE FROM commits WHERE id=?1", [*id])?;
            for key in keys {
                execute(
                    sql,
                    "UPDATE activity SET last_touch_unix_ms=coalesce(
                    (SELECT max(at_unix_ms) FROM touches WHERE target_kind='file'
                     AND target_key=?1 AND restricted_record IS NULL),0)
                    WHERE target_kind='file' AND target_key=?1",
                    [&key],
                )?;
                execute(
                    sql,
                    "DELETE FROM activity WHERE target_kind='file'
                    AND target_key=?1 AND inbound_resolved=0
                    AND NOT EXISTS(SELECT 1 FROM touches WHERE target_kind='file'
                                   AND target_key=?1 AND restricted_record IS NULL)",
                    [&key],
                )?;
            }
        }
        // A fully referenced excess remains explicit; callers must report a
        // retention capacity shortage instead of retrying without progress.
        Ok(excess > ids.len() as i64)
    })
}
fn query<T: rusqlite::types::FromSql, P: rusqlite::Params>(
    view: &SqlView<'_>,
    sql: &str,
    params: P,
) -> AtlasResult<T> {
    view.prepare(sql)?
        .query_row(params, |r| r.get(0))
        .map_err(cache_error)
}
fn execute<P: rusqlite::Params>(view: &SqlView<'_>, sql: &str, params: P) -> AtlasResult<usize> {
    view.prepare(sql)?.execute(params).map_err(cache_error)
}
