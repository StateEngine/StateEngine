mod body;
mod metadata;
mod retired_decision;
pub(crate) use body::body;
pub(crate) use metadata::metadata;
pub(crate) mod capture;
pub(crate) mod event;
mod maintenance;
#[cfg(test)]
mod materialized_text_review;
pub(crate) mod process;
pub(crate) mod semantic;
pub(crate) mod session;
// Closed wave-1 metadata codec; text lives only in its typed payload column.
use crate::{error::*, identity::*, *};
use rusqlite::Connection;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
pub(crate) fn encode<T: Serialize>(v: &T) -> StoreResult<String> {
    serde_json::to_string(v).map_err(invalid)
}
pub(crate) fn field<T: DeserializeOwned>(v: &Value, k: &str) -> StoreResult<T> {
    serde_json::from_value(
        v.get(k)
            .cloned()
            .ok_or_else(|| invalid(format!("missing stored field {k}")))?,
    )
    .map_err(invalid)
}
pub(crate) fn aux(c: &Connection, seq: i64, v: Value) -> StoreResult<()> {
    c.execute(
        "INSERT INTO aux_data(event_seq,facts) VALUES(?,?)",
        crate::sql_value::sql_params![seq, encode(&v)?],
    )
    .map_err(sql)?;
    Ok(())
}
pub(crate) fn facts(c: &Connection, seq: i64) -> StoreResult<Value> {
    let s: String = c
        .prepare_cached("SELECT facts FROM aux_data WHERE event_seq=?")
        .map_err(sql)?
        .query_row([seq], |r| crate::sql_value::value(r, 0))
        .map_err(sql)?;
    serde_json::from_str(&s).map_err(invalid)
}
/// Stored text is always the materialized inline form: staged handles are
/// materialized by staging::prepare before apply, so this boundary cannot
/// receive one.
pub(crate) fn text(text: &str, max: usize) -> StoreResult<String> {
    if text.len() > max {
        return Err(fail(
            StoreErrorCode::BodyTooLarge,
            format!("text is {} bytes; limit {max}", text.len()),
        ));
    }
    Ok(text.to_string())
}
pub(crate) fn stored_text(c: &Connection, seq: i64, field: &str) -> StoreResult<StoredText> {
    use rusqlite::OptionalExtension;
    let erased: Option<Vec<u8>> = c
        .query_row(
            "SELECT erasure_id FROM erased_fields WHERE event_seq=? AND field=?",
            rusqlite::params![seq, field],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(erasure) = erased {
        return Ok(StoredText::Erased {
            erasure: capture::record(erasure)?,
        });
    }
    let (length, encoding, hash): (u64, String, Vec<u8>) = c
        .prepare_cached(
            "SELECT length(content),encoding,sha256 FROM payloads WHERE event_seq=? AND field=?",
        )
        .map_err(sql)?
        .query_row(crate::sql_value::sql_params![seq, field], |r| {
            Ok((
                crate::sql_value::value(r, 0)?,
                crate::sql_value::value(r, 1)?,
                crate::sql_value::value(r, 2)?,
            ))
        })
        .map_err(sql)?;
    if length > 1024 * 1024 || encoding != "utf8" || hash.len() != 32 {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "stored text length/encoding/hash is invalid",
        ));
    }
    let bytes: Vec<u8> = c
        .prepare_cached("SELECT content FROM payloads WHERE event_seq=? AND field=?")
        .map_err(sql)?
        .query_row(crate::sql_value::sql_params![seq, field], |r| {
            crate::sql_value::value(r, 0)
        })
        .map_err(sql)?;
    use sha2::{Digest, Sha256};
    if Sha256::digest(&bytes).as_slice() != hash {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "stored text hash differs from its immutable payload",
        ));
    }
    Ok(StoredText::Present(String::from_utf8(bytes).map_err(
        |e| fail(StoreErrorCode::Unreadable, e.to_string()),
    )?))
}
pub(crate) fn revision(value: u64) -> StoreResult<Revision> {
    if value > i64::MAX as u64 {
        return Err(invalid("entity revision exceeds store range"));
    }
    Ok(Revision {
        value: std::num::NonZeroU64::new(value).ok_or_else(|| invalid("zero entity revision"))?,
    })
}
