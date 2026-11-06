//! Rank version 4 follows §1.5. Weights change only against the independent benchmark.
mod identifiers;
use crate::{
    cache::connection::SqlView,
    errors::{AtlasResult, cache_error},
    query::RecordReader,
};
pub(crate) use identifiers::split_matches;
pub use identifiers::{identifier_index, identifier_tokens};
use rusqlite::params;
use se_types::{Read, code::*};
pub const VERSION: u32 = 4;
#[derive(Default)]
pub struct Activity {
    pub score: f64,
    pub last: Option<i64>,
    pub edited_by: Option<se_types::AgentId>,
    pub cited_messages: u32,
}
pub struct ActivityQuery<'a> {
    pub project: &'a se_types::ProjectId,
    pub viewer: &'a AtlasPrincipal,
    pub records: &'a dyn RecordReader,
    pub now: Option<i64>,
}
pub fn activity(
    sql: &SqlView<'_>,
    kind: &str,
    key: &[u8],
    query: ActivityQuery<'_>,
) -> AtlasResult<Activity> {
    let mut stmt=sql.prepare("SELECT touch_kind,actor,at_unix_ms,source_record FROM touches WHERE target_kind=?1 AND target_key=?2 ORDER BY at_unix_ms DESC,ordinal DESC LIMIT 10")?;
    let mut rows = stmt.query(params![kind, key]).map_err(cache_error)?;
    let mut activity = Activity::default();
    while let Some(row) = rows.next().map_err(cache_error)? {
        let touch: String = row.get(0).map_err(cache_error)?;
        let actor: Option<String> = row.get(1).map_err(cache_error)?;
        let at: i64 = row.get(2).map_err(cache_error)?;
        let record: Option<i64> = row.get(3).map_err(cache_error)?;
        if let Some(record) = record {
            let mut record_stmt =
                sql.prepare("SELECT record_id,kind,source_event FROM records WHERE id=?1")?;
            let pointer = record_stmt
                .query_row([record], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .map_err(cache_error)?;
            let pointer = RecordPointer {
                key: RecordKey::new(pointer.0)?,
                kind: serde_json::from_value(serde_json::Value::String(pointer.1))
                    .map_err(cache_error)?,
                source_event: pointer.2.parse()?,
            };
            match query
                .records
                .read(query.project, query.viewer, &pointer, None)?
            {
                Read::Present { value } if value.pointer == pointer => (),
                Read::Absent { .. } => continue,
                _ => return Err(cache_error("activity record authority unavailable")),
            }
        }
        let actor = actor
            .map(|text| serde_json::from_str::<AtlasActor>(&text).map_err(cache_error))
            .transpose()?;
        let own = actor.as_ref().is_some_and(|a| &a.principal == query.viewer);
        let weight = match touch.as_str() {
            "commit" => 1.0,
            "edit" | "tool_edit" => {
                if own {
                    2.0
                } else {
                    1.0
                }
            }
            "ratified_decision" => 1.0,
            "decision" | "message" | "working" => 0.5,
            _ => return Err(cache_error("unknown activity touch kind")),
        };
        if let Some(now) = query.now {
            let age = (now.saturating_sub(at).max(0) as f64 / 86_400_000.0).max(1.0 / 24.0);
            activity.score += weight / age.sqrt();
        }
        activity.last = Some(activity.last.map_or(at, |old| old.max(at)));
        if touch == "message" {
            activity.cited_messages += 1;
        }
        if touch == "edit" && activity.edited_by.is_none() {
            activity.edited_by = actor.and_then(|a| match a.principal {
                AtlasPrincipal::Agent(id) => Some(id),
                _ => None,
            });
        }
    }
    let mut stmt = sql
        .prepare("SELECT inbound_resolved FROM activity WHERE target_kind=?1 AND target_key=?2")?;
    let mut rows = stmt.query(params![kind, key]).map_err(cache_error)?;
    if let Some(row) = rows.next().map_err(cache_error)? {
        let count: i64 = row.get(0).map_err(cache_error)?;
        if count < 0 {
            return Err(cache_error("negative inbound reference count"));
        }
        activity.score += 0.3 * (1.0 + count as f64).log2();
    }
    Ok(activity)
}
pub fn downweight(path: &str, asked: SearchKind) -> bool {
    !matches!(asked, SearchKind::Path | SearchKind::Text)
        && (path
            .split('/')
            .any(|part| matches!(part, "docs" | "doc" | "tests" | "test" | "__tests__"))
            || path.ends_with(".md")
            || path.contains(".generated.")
            || path.contains(".test.")
            || path.contains(".spec."))
}
