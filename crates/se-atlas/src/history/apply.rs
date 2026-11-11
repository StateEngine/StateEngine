//! Atomic cache-only ingestion; denied paths are discarded before derivation.
use super::*;
use crate::{
    cache::connection::{CacheConnection, SqlView},
    policy::built_in_denied,
};
use rusqlite::{OptionalExtension, params};
use std::time::Instant;

pub fn ingest(
    cache: &mut CacheConnection<'_>,
    feed: &HistoryFeed,
    deadline: Instant,
) -> AtlasResult<HistoryReceipt> {
    feed.validate()?;
    if !cache.checkpoint(deadline)? {
        return Err(cache_error(
            "Git history is waiting for external readers to release the bounded WAL",
        ));
    }
    cache.write(4_000_000, deadline, |sql| apply(sql, feed))
}
/// The owner may call this inside its existing contained cold transaction. It
/// opens no connection, raises no profile, and grants no publication authority.
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn apply(sql: &SqlView<'_>, feed: &HistoryFeed) -> AtlasResult<HistoryReceipt> {
    feed.validate()?;
    let (project, root, generation, serial): (String, String, i64, i64) = sql
        .prepare(
            "SELECT project,root,index_generation,observed_serial FROM meta WHERE singleton=1",
        )?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(cache_error)?;
    if generation < 0 || serial < 0 {
        return Err(cache_error("negative Atlas history fence"));
    }
    let active: bool = sql
        .prepare("SELECT EXISTS(SELECT 1 FROM active_batch)")?
        .query_row([], |r| r.get(0))
        .map_err(cache_error)?;
    if active {
        return Err(cache_error(
            "finish the active file batch before publishing Git history",
        ));
    }
    if project != feed.project.as_str() || root != feed.root.as_str() {
        return Err(cache_error(
            "Git history feed belongs to another registered root",
        ));
    }
    let saved: Option<String> = sql
        .prepare("SELECT history_bound FROM record_feed WHERE singleton=1")?
        .query_row([], |r| r.get(0))
        .map_err(cache_error)?;
    let retained = saved
        .map(|s| serde_json::from_str::<HistoryBound>(&s).map_err(cache_error))
        .transpose()?;
    if retained.as_ref() == Some(&feed.bound) {
        // A same-bound retry still verifies immutable commit facts. A conflicting
        // producer must not hide behind an already advanced cursor.
        verify(sql, feed)?;
        return Ok(HistoryReceipt {
            changed: 0,
            denied_paths: 0,
            generation: Generation(generation as u64),
            replay: true,
        });
    }
    if retained != feed.expected {
        return Err(cache_error(
            "Git history cursor changed; reread its bound before retrying",
        ));
    }
    let next = generation
        .checked_add(1)
        .ok_or_else(|| cache_error("Git history generation overflow"))?;
    sql.prepare("INSERT INTO generations VALUES(?1,?2,?3,'History')")?
        .execute(params![next, feed.observed_unix_ms, serial])
        .map_err(cache_error)?;
    let mut changed = 0;
    let mut denied_paths = 0;
    for commit in &feed.commits {
        let mut paths = Vec::with_capacity(commit.paths.len());
        for path in &commit.paths {
            if built_in_denied(path) {
                denied_paths += 1;
            } else if !paths.contains(&path) {
                paths.push(path);
            }
        }
        // No author, subject, touch or mention is derived for secret-only commits.
        // Their traversal position remains explicit without retaining those facts.
        if paths.is_empty() {
            continue;
        }
        let id = upsert(sql, commit)?;
        let oid = object(&commit.oid)?;
        sql.prepare("INSERT OR IGNORE INTO observed_commits VALUES(?1,?2)")?
            .execute(params![&oid, next])
            .map_err(cache_error)?;
        for path in paths {
            let key: Option<Vec<u8>> = sql
                .prepare("SELECT key FROM files WHERE path=?1")?
                .query_row([path.as_str()], |r| r.get(0))
                .optional()
                .map_err(cache_error)?;
            if let Some(key) = key {
                sql.prepare(
                    "INSERT OR IGNORE INTO mentions VALUES('commit',?1,'file',?2,'ExplicitImport')",
                )?
                .execute(params![id, &key])
                .map_err(cache_error)?;
                file_touch(sql, id, &key, commit.author_unix_ms)?;
            }
        }
        // Commit-owned rows retire with commits_links_delete. File authorship is
        // deliberately untouched: a path-only diff proves no current revision.
        sql.prepare("INSERT OR IGNORE INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms) VALUES('commit',?1,0,'commit',NULL,?2)")?.execute(params![&oid,commit.author_unix_ms]).map_err(cache_error)?;
        sql.prepare("INSERT INTO activity VALUES('commit',?1,?2,0) ON CONFLICT(target_kind,target_key) DO UPDATE SET last_touch_unix_ms=excluded.last_touch_unix_ms")?.execute(params![&oid,commit.author_unix_ms]).map_err(cache_error)?;
        changed += 1;
    }
    sql.prepare("UPDATE record_feed SET last_oid=?1,history_bound=?2 WHERE singleton=1")?
        .execute(params![
            object(&feed.bound.head)?,
            serde_json::to_string(&feed.bound).map_err(cache_error)?
        ])
        .map_err(cache_error)?;
    sql.prepare("UPDATE meta SET index_generation=?1,published_generation=?1 WHERE singleton=1")?
        .execute([next])
        .map_err(cache_error)?;
    Ok(HistoryReceipt {
        changed,
        denied_paths,
        generation: Generation(next as u64),
        replay: false,
    })
}
type CommitFacts = (i64, i64, String, String, Option<Vec<u8>>);
fn facts(sql: &SqlView<'_>, commit: &Commit) -> AtlasResult<Option<CommitFacts>> {
    sql.prepare("SELECT id,author_unix_ms,author,subject,parent_oid FROM commits WHERE oid=?1")?
        .query_row([object(&commit.oid)?], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()
        .map_err(cache_error)
}
fn upsert(sql: &SqlView<'_>, commit: &Commit) -> AtlasResult<i64> {
    let parent = commit.parent.as_deref().map(object).transpose()?;
    if let Some((id, time, author, subject, old_parent)) = facts(sql, commit)? {
        if time != commit.author_unix_ms
            || author != commit.author
            || subject != commit.subject
            || old_parent != parent
        {
            return Err(cache_error(
                "immutable Git commit metadata conflicts; prior cache preserved",
            ));
        }
        return Ok(id);
    }
    sql.prepare(
        "INSERT INTO commits(oid,author_unix_ms,author,subject,parent_oid) VALUES(?1,?2,?3,?4,?5)",
    )?
    .execute(params![
        object(&commit.oid)?,
        commit.author_unix_ms,
        &commit.author,
        &commit.subject,
        parent
    ])
    .map_err(cache_error)?;
    facts(sql, commit)?
        .map(|r| r.0)
        .ok_or_else(|| cache_error("inserted Git commit is absent on transaction readback"))
}
fn verify(sql: &SqlView<'_>, feed: &HistoryFeed) -> AtlasResult<()> {
    for commit in &feed.commits {
        if commit.paths.iter().all(built_in_denied) {
            continue;
        }
        if facts(sql, commit)?.is_none() {
            return Err(cache_error(
                "Git cursor points past absent retained commit metadata",
            ));
        }
        upsert(sql, commit)?;
    }
    Ok(())
}

/// A Git path diff is activity, never proof of current-content authorship or an
/// Atlas principal. The commit FK retires its file seeds on retention pruning.
fn file_touch(sql: &SqlView<'_>, commit: i64, key: &[u8], at: i64) -> AtlasResult<()> {
    sql.prepare(
        "INSERT OR IGNORE INTO touches(
        target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_commit)
        SELECT 'file',?1,coalesce(max(ordinal),0)+1,'commit',NULL,?2,?3
        FROM touches WHERE target_kind='file' AND target_key=?1",
    )?
    .execute(params![key, at, commit])
    .map_err(cache_error)?;
    sql.prepare(
        "DELETE FROM touches WHERE target_kind='file' AND target_key=?1
        AND ordinal NOT IN (SELECT ordinal FROM touches
            WHERE target_kind='file' AND target_key=?1
            ORDER BY at_unix_ms DESC,ordinal DESC LIMIT 10)",
    )?
    .execute([key])
    .map_err(cache_error)?;
    sql.prepare(
        "INSERT INTO activity(target_kind,target_key,last_touch_unix_ms,inbound_resolved)
        SELECT 'file',?1,max(at_unix_ms),0 FROM touches
        WHERE target_kind='file' AND target_key=?1 AND restricted_record IS NULL HAVING count(*)>0
        ON CONFLICT(target_kind,target_key)
        DO UPDATE SET last_touch_unix_ms=excluded.last_touch_unix_ms",
    )?
    .execute([key])
    .map_err(cache_error)?;
    Ok(())
}
