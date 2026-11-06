use crate::{
    cache::connection::{CacheConnection, SqlView},
    errors::{AtlasResult, cache_error},
    model::*,
    queries::*,
};
use rusqlite::{OptionalExtension, params};
use std::time::Instant;

#[derive(Debug)]
pub struct FeedReceipt {
    pub through: se_types::EventId,
    pub changed: u32,
    pub complete: bool,
}
pub fn apply(
    cache: &CacheConnection<'_>,
    feed: &RecordFeed,
    deadline: Instant,
) -> AtlasResult<FeedReceipt> {
    feed.validate()?;
    if feed.project != cache.identity().scope.registration.project {
        return Err(cache_error("record feed belongs to another project"));
    }
    cache.write(2_000_000, deadline, |sql| {
        let saved: Option<String> = sql
            .prepare("SELECT last_event FROM record_feed WHERE singleton=1")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)?;
        if saved.as_deref() == Some(feed.through.as_str()) {
            return Ok(FeedReceipt {
                through: feed.through.clone(),
                changed: 0,
                complete: feed.complete,
            });
        }
        if saved.as_deref() != feed.after.as_ref().map(se_types::EventId::as_str) {
            return Err(se_types::SeError::new(se_types::Detail::RevisionConflict(
                se_types::details::RevisionConflict {
                    entity: "Atlas record feed".into(),
                    expected: feed
                        .after
                        .as_ref()
                        .map_or("absent".into(), ToString::to_string),
                    current: saved.unwrap_or_else(|| "absent".into()),
                },
            )));
        }
        for change in &feed.changes {
            match change {
                RecordFeedChange::Remove { key, .. } => remove(sql, key)?,
                RecordFeedChange::Upsert(record) => upsert(sql, record)?,
                RecordFeedChange::Ratify {
                    key, source_event, ..
                } => ratify(sql, key, source_event)?,
            }
        }
        sql.prepare("UPDATE record_feed SET last_event=?1 WHERE singleton=1")?
            .execute([feed.through.as_str()])
            .map_err(cache_error)?;
        // A feed commit can change candidates and activity ordering even when
        // no source file changed. Fence live query continuations atomically with
        // the record cursor; the code-change publication fence remains separate.
        sql.prepare("UPDATE meta SET index_generation=index_generation+1 WHERE singleton=1")?
            .execute([])
            .map_err(cache_error)?;
        Ok(FeedReceipt {
            through: feed.through.clone(),
            changed: feed.changes.len() as u32,
            complete: feed.complete,
        })
    })
}
fn ratify(sql: &SqlView<'_>, key: &RecordKey, event: &se_types::EventId) -> AtlasResult<()> {
    let id: Option<i64> = sql
        .prepare(
            "SELECT id FROM records WHERE record_id=?1 AND kind='decision' AND source_event=?2",
        )?
        .query_row(params![key.as_str(), event.as_str()], |row| row.get(0))
        .optional()
        .map_err(cache_error)?;
    let id=id.ok_or_else(||cache_error("ratification is missing its matching committed decision upsert; replay the same source chunk"))?;
    sql.prepare("UPDATE touches SET touch_kind='ratified_decision' WHERE source_record=?1")?
        .execute([id])
        .map_err(cache_error)?;
    Ok(())
}

fn remove(sql: &SqlView<'_>, key: &RecordKey) -> AtlasResult<()> {
    let old = affected(sql, key)?;
    // FTS and source-record touches are deleted by the schema's owned triggers.
    sql.prepare("DELETE FROM records WHERE record_id=?1")?
        .execute([key.as_str()])
        .map_err(cache_error)?;
    refresh(sql, old)
}
fn upsert(sql: &SqlView<'_>, record: &FeedRecord) -> AtlasResult<()> {
    record.validate()?;
    // Preserve the row identity and incoming links while atomically replacing
    // outgoing mentions and tokens. A delete/reinsert would lose incoming links.
    let old = affected(sql, &record.pointer.key)?;
    let visibility = match record.visibility {
        RecordVisibility::Project => "project",
        _ => "restricted",
    };
    let audience = match &record.visibility {
        RecordVisibility::Restricted {
            audience: Some(keys),
        } => Some(serde_json::to_vec(keys).map_err(cache_error)?),
        _ => None,
    };
    let actor = record
        .actor
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(cache_error)?;
    let id: Option<i64> = sql
        .prepare("SELECT id FROM records WHERE record_id=?1")?
        .query_row([record.pointer.key.as_str()], |r| r.get(0))
        .optional()
        .map_err(cache_error)?;
    let statement = if id.is_some() {
        "UPDATE records SET kind=?2,actor=?3,occurred_unix_ms=?4,title=?5,source_event=?6,visibility=?7,audience=?8,body_truncated=?9 WHERE record_id=?1"
    } else {
        "INSERT INTO records(record_id,kind,actor,occurred_unix_ms,title,source_event,visibility,audience,body_truncated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)"
    };
    sql.prepare(statement)?
        .execute(params![
            record.pointer.key.as_str(),
            kind_name(record.pointer.kind),
            actor,
            record.occurred_unix_ms,
            record.title,
            record.pointer.source_event.as_str(),
            visibility,
            audience,
            record.body_truncated
        ])
        .map_err(cache_error)?;
    let id: i64 = sql
        .prepare("SELECT id FROM records WHERE record_id=?1")?
        .query_row([record.pointer.key.as_str()], |r| r.get(0))
        .map_err(cache_error)?;
    for statement in [
        "DELETE FROM record_fts WHERE rowid=?1",
        "DELETE FROM record_text_fts WHERE rowid=?1",
        "DELETE FROM mentions WHERE source_kind='record' AND source_id=?1",
        "DELETE FROM touches WHERE source_record=?1",
    ] {
        sql.prepare(statement)?.execute([id]).map_err(cache_error)?;
    }
    refresh(sql, old)?;
    sql.prepare("INSERT INTO record_fts(rowid,title,kind) VALUES(?1,?2,?3)")?
        .execute(params![id, record.title, kind_name(record.pointer.kind)])
        .map_err(cache_error)?;
    sql.prepare("INSERT INTO record_text_fts(rowid,body) VALUES(?1,?2)")?
        .execute(params![id, record.body])
        .map_err(cache_error)?;
    super::mentions::apply(sql, id, record)?;
    Ok(())
}
pub(super) fn kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Decision => "decision",
        RecordKind::Message => "message",
        RecordKind::Working => "working",
        RecordKind::Edit => "edit",
        RecordKind::Commit => "commit",
    }
}

fn affected(sql: &SqlView<'_>, key: &RecordKey) -> AtlasResult<Vec<(String, Vec<u8>)>> {
    let mut stmt=sql.prepare("SELECT DISTINCT target_kind,target_key FROM touches WHERE source_record IN (SELECT id FROM records WHERE record_id=?1) LIMIT 257")?;
    let mut rows = stmt.query([key.as_str()]).map_err(cache_error)?;
    let mut output = Vec::new();
    while let Some(row) = rows.next().map_err(cache_error)? {
        if output.len() == 256 {
            return Err(cache_error(
                "record touch set exceeds its admitted mention bound",
            ));
        }
        output.push((
            row.get(0).map_err(cache_error)?,
            row.get(1).map_err(cache_error)?,
        ));
    }
    Ok(output)
}
fn refresh(sql: &SqlView<'_>, keys: Vec<(String, Vec<u8>)>) -> AtlasResult<()> {
    for (kind, key) in keys {
        sql.prepare("DELETE FROM activity WHERE target_kind=?1 AND target_key=?2 AND inbound_resolved=0 AND NOT EXISTS(SELECT 1 FROM touches WHERE target_kind=?1 AND target_key=?2 AND restricted_record IS NULL)")?
            .execute(params![kind,key]).map_err(cache_error)?;
        sql.prepare("UPDATE activity SET last_touch_unix_ms=(SELECT max(at_unix_ms) FROM touches WHERE target_kind=?1 AND target_key=?2 AND restricted_record IS NULL) WHERE target_kind=?1 AND target_key=?2")?
            .execute(params![kind,key]).map_err(cache_error)?;
    }
    Ok(())
}
