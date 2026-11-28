//! Decode a published turn from its structural row and optional erasable body.
use super::*;
use crate::published_turn::{DiffCounts, PublishedTurn, TurnNesting, TurnUsage};
use rusqlite::OptionalExtension;
use se_types::SessionId;

pub(crate) fn decode(
    c: &Connection,
    seq: i64,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    let s = scope_key(c, scope, false)?;
    let mut q = c
        .prepare_cached("SELECT * FROM published_turns WHERE event_seq=?")
        .map_err(sql)?;
    let mut rows = q.query([seq]).map_err(sql)?;
    let row = rows
        .next()
        .map_err(sql)?
        .ok_or_else(|| invalid("published turn fact absent"))?;
    let get = |name: &str| -> StoreResult<rusqlite::types::Value> { row.get(name).map_err(sql) };
    let text = |name: &str| -> StoreResult<String> { row.get(name).map_err(sql) };
    let session: SessionId = wire(
        c,
        "session",
        &row.get::<_, Vec<u8>>("session_id").map_err(sql)?,
        &s,
    )?
    .try_into()
    .map_err(invalid)?;
    let agent = decode_agent(
        c,
        wire(
            c,
            "agent",
            &row.get::<_, Vec<u8>>("agent_id").map_err(sql)?,
            &s,
        )?,
        &s,
    )?;
    let usage = usage(row)?;
    let diff = diff(row)?;
    let nesting = nesting(c, row, &s)?;
    let digest: Option<Vec<u8>> = row.get("content_sha256").map_err(sql)?;
    let content_sha256 = digest
        .map(|d| <[u8; 32]>::try_from(d).map_err(|_| invalid("published turn digest length")))
        .transpose()?;
    let has_payload = !matches!(get("body_payload")?, rusqlite::types::Value::Null);
    let turn = PublishedTurn {
        agent,
        session,
        conversation: text("conversation")?,
        harness: text("harness")?,
        model_provider: text("model_provider")?,
        model: text("model")?,
        vendor_turn: text("vendor_turn")?,
        occurred_at_us: row.get("occurred_at_us").map_err(sql)?,
        role: capture::parse_role(&text("role")?)?,
        body_omitted_bytes: count(row, "body_omitted_bytes")?.unwrap_or(0),
        content_sha256,
        content_verified: row.get("content_verified").map_err(sql)?,
        usage,
        diff,
        nesting,
    };
    drop(rows);
    let erased: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM erased_fields WHERE event_seq=? AND field='body')",
            [seq],
            |r| crate::sql_value::value(r, 0),
        )
        .optional()
        .map_err(sql)?
        .unwrap_or(false);
    let body = if has_payload || erased {
        Some(stored_text(c, seq, "body")?)
    } else {
        None
    };
    Ok(EventBody::SessionTurnPublished { turn, body })
}

fn count(row: &rusqlite::Row<'_>, name: &str) -> StoreResult<Option<u64>> {
    row.get::<_, Option<i64>>(name)
        .map_err(sql)?
        .map(|v| u64::try_from(v).map_err(|_| invalid("negative published turn count")))
        .transpose()
}
/// Usage is all four counts or none; a partial row is unreadable, never zero.
fn usage(row: &rusqlite::Row<'_>) -> StoreResult<Option<TurnUsage>> {
    Ok(
        match (
            count(row, "input_tokens")?,
            count(row, "output_tokens")?,
            count(row, "cache_read_tokens")?,
            count(row, "cache_write_tokens")?,
        ) {
            (
                Some(input_tokens),
                Some(output_tokens),
                Some(cache_read_tokens),
                Some(cache_write_tokens),
            ) => Some(TurnUsage {
                input_tokens,
                output_tokens,
                cache_read_tokens,
                cache_write_tokens,
                cost_usd: row.get("cost_usd").map_err(sql)?,
            }),
            (None, None, None, None) => None,
            _ => return Err(invalid("partial published turn usage")),
        },
    )
}
fn diff(row: &rusqlite::Row<'_>) -> StoreResult<Option<DiffCounts>> {
    Ok(
        match (
            count(row, "files_changed")?,
            count(row, "insertions")?,
            count(row, "deletions")?,
        ) {
            (Some(files_changed), Some(insertions), Some(deletions)) => Some(DiffCounts {
                files_changed,
                insertions,
                deletions,
            }),
            (None, None, None) => None,
            _ => return Err(invalid("partial published turn diff counts")),
        },
    )
}
fn nesting(
    c: &Connection,
    row: &rusqlite::Row<'_>,
    scope: &[u8],
) -> StoreResult<Option<TurnNesting>> {
    let Some(parent) = row
        .get::<_, Option<Vec<u8>>>("parent_session_id")
        .map_err(sql)?
    else {
        return Ok(None);
    };
    Ok(Some(TurnNesting {
        parent_session: wire(c, "session", &parent, scope)?
            .try_into()
            .map_err(invalid)?,
        nested_agent: row.get("nested_agent").map_err(sql)?,
        depth: row.get("nesting_depth").map_err(sql)?,
    }))
}
