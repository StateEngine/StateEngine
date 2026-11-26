//! Erasure projections: the explicit privacy exception to append-only history.
//! Each removal runs under a permit for one exact row; the triggers refuse the rest.
use super::permit;
use crate::{connection::payload, error::*, identity::key, *};
use rusqlite::{Connection, OptionalExtension};
use se_types::EventId;

/// The canonical manifest an erasure commits to before any body is removed,
/// with the backup generations its cleanup replaces once they were pinned.
pub(crate) fn manifest(
    erasure: &RecordId,
    targets: &[EraseTarget],
    residuals: &[ResidualCopy],
    generations: Option<&[RecordId]>,
) -> String {
    let mut value = serde_json::json!({
        "erasure": uuid::Uuid::from_bytes(*erasure.as_bytes()).to_string(),
        "targets": targets.iter().map(|t| serde_json::json!({
            "event": t.event.as_str(),
            "expected": t.expected.value.get(),
        })).collect::<Vec<_>>(),
        "residuals": residuals.iter().map(|r| serde_json::json!({
            "custodian": r.custodian,
            "location": r.location,
            "reason": r.reason,
        })).collect::<Vec<_>>(),
    });
    if let Some(generations) = generations {
        value["generations"] = serde_json::json!(
            generations
                .iter()
                .map(|id| uuid::Uuid::from_bytes(*id.as_bytes()).to_string())
                .collect::<Vec<_>>()
        );
    }
    value.to_string()
}
fn erasure_key(erasure: &RecordId) -> StoreResult<Vec<u8>> {
    Ok(erasure.as_bytes().to_vec())
}
pub(crate) fn requested(
    c: &Connection,
    seq: i64,
    erasure: &RecordId,
    targets: &[EraseTarget],
    residuals: &[ResidualCopy],
    generations: Option<&[RecordId]>,
) -> StoreResult<()> {
    if targets.is_empty()
        || targets.len() > 60
        || residuals.len() > super::MAX_RESIDUALS
        || generations.is_some_and(|g| g.len() > super::MAX_RESIDUALS)
    {
        return Err(invalid(
            "erasure needs 1..60 targets and at most 64 residuals and backup generations",
        ));
    }
    let manifest = payload(
        c,
        seq,
        "manifest",
        &manifest(erasure, targets, residuals, generations),
    )?;
    c.execute(
        "INSERT INTO erasures(erasure_id,requested_seq,completed_seq,manifest_payload) VALUES(?,?,NULL,?)",
        crate::sql_value::sql_params![erasure_key(erasure)?, seq, manifest],
    )
    .map_err(sql)?;
    Ok(())
}
/// The target must be a still-present body of the requested kind, named in an
/// open erasure, at the revision the plan recorded and the size the event states.
pub(crate) fn body(
    c: &Connection,
    scope: &[u8],
    target: &EventId,
    erasure: &RecordId,
    original_bytes: u64,
    kind: &str,
) -> StoreResult<()> {
    let id = key(c, "event", target.as_str(), scope, false)?;
    let (seq, stored_kind, operation): (i64, String, Vec<u8>) = c
        .query_row(
            "SELECT seq,kind,operation_id FROM events WHERE event_id=?",
            [id],
            |r| {
                Ok((
                    crate::sql_value::value(r, 0)?,
                    crate::sql_value::value(r, 1)?,
                    crate::sql_value::value(r, 2)?,
                ))
            },
        )
        .optional()
        .map_err(sql)?
        .ok_or_else(|| {
            fail(
                StoreErrorCode::ReferenceMissing,
                "erasure target event is absent",
            )
        })?;
    let erasure_id = erasure_key(erasure)?;
    let open: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM erasures WHERE erasure_id=? AND completed_seq IS NULL)",
            [&erasure_id],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    if !open {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "body erasure names no open erasure request",
        ));
    }
    // Work mail keeps its body payload without a projection column to clear.
    let (table, column) = match (kind, stored_kind.as_str()) {
        ("turn", "session.turn") => ("turn_data", Some("text_payload")),
        ("message", "message.sent") => ("message_data", Some("body_payload")),
        ("message", "message.work_sent") => ("payloads", None),
        _ => {
            return Err(fail(
                StoreErrorCode::InvalidTransition,
                "erasure target kind differs from the erasure event",
            ));
        }
    };
    let lookup = match column {
        Some(column) => format!(
            "SELECT p.payload_id,length(p.content) FROM {table} d JOIN payloads p ON p.payload_id=d.{column} WHERE d.event_seq=?"
        ),
        None => {
            "SELECT payload_id,length(content) FROM payloads WHERE event_seq=? AND field='body'"
                .into()
        }
    };
    let found: Option<(i64, u64)> = c
        .query_row(&lookup, [seq], |r| {
            Ok((
                crate::sql_value::value(r, 0)?,
                crate::sql_value::value(r, 1)?,
            ))
        })
        .optional()
        .map_err(sql)?;
    let Some((payload_id, bytes)) = found else {
        return Err(fail(
            StoreErrorCode::ContentErased,
            "erasure target has no present body",
        ));
    };
    if bytes != original_bytes {
        return Err(fail(
            StoreErrorCode::SourceChanged,
            "erasure target body size differs from the plan",
        ));
    }
    {
        let _allowed = permit::body(seq, "body");
        if let Some(column) = column {
            let digest = if table == "turn_data" {
                ",source_sha256=NULL"
            } else {
                ""
            };
            c.execute(
                &format!("UPDATE {table} SET {column}=NULL{digest} WHERE event_seq=?"),
                [seq],
            )
            .map_err(sql)?;
        }
        c.execute("DELETE FROM payloads WHERE payload_id=?", [payload_id])
            .map_err(sql)?;
    }
    c.execute(
        "INSERT INTO erased_fields(event_seq,field,original_bytes,erasure_id) VALUES(?,'body',?,?)",
        crate::sql_value::sql_params![seq, bytes, erasure_id],
    )
    .map_err(sql)?;
    drop_fingerprint(c, operation)
}
/// The request fingerprint digests the body; keep the operation, drop the digest.
fn drop_fingerprint(c: &Connection, operation: Vec<u8>) -> StoreResult<()> {
    let erased: bool = c
        .query_row(
            "SELECT erased FROM operations WHERE operation_id=?",
            [&operation],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    if !erased {
        let _allowed = permit::operation(operation.clone());
        c.execute(
            "UPDATE operations SET erased=1,fingerprint=NULL WHERE operation_id=?",
            [operation],
        )
        .map_err(sql)?;
    }
    Ok(())
}
pub(crate) fn completed(c: &Connection, seq: i64, erasure: &RecordId) -> StoreResult<()> {
    let changed = c
        .execute(
            "UPDATE erasures SET completed_seq=? WHERE erasure_id=? AND completed_seq IS NULL",
            crate::sql_value::sql_params![seq, erasure_key(erasure)?],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "erasure completion names no open erasure request",
        ));
    }
    Ok(())
}
