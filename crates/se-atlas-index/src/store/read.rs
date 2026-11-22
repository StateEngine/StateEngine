//! Read helpers that present base tables and pending deltas as one index.
//!
//! A posting list is the base `vocab_post` blob with `post_delta` applied
//! (tf 0 removes a file). While a cold build is still publishing, files
//! numbered above the build's watermark are found through `file_tok`, so a
//! reader sees every committed batch before the final postings land.
use super::{open_connection, schema, varint};
use crate::Result;
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

/// A read-only connection. It never opens a write transaction.
pub struct Reader {
    conn: Connection,
}

impl Reader {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = open_connection(path, false)?;
        schema::configure_reader(&conn)?;
        Ok(Self { conn })
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn token_id(&self, token: &str) -> Result<Option<i64>> {
        token_id(&self.conn, token)
    }

    pub fn read_postings(&self, tok: i64) -> Result<Vec<(i64, u32)>> {
        read_postings(&self.conn, tok)
    }

    pub fn effective_df(&self, tok: i64) -> Result<u64> {
        effective_df(&self.conn, tok)
    }

    pub fn gram_tokens(&self, gram: u32) -> Result<Vec<i64>> {
        gram_tokens(&self.conn, i64::from(gram))
    }
}

pub fn token_id(conn: &Connection, token: &str) -> Result<Option<i64>> {
    Ok(conn
        .prepare_cached("SELECT id FROM vocab WHERE tok=?1")?
        .query_row([token], |row| row.get(0))
        .optional()?)
}

/// Every `(file, tf)` holding the token, sorted by file.
pub fn read_postings(conn: &Connection, tok: i64) -> Result<Vec<(i64, u32)>> {
    let mut merged = apply_deltas(base_postings(conn, tok)?, &deltas(conn, tok)?);
    if let Some(after) = cold_watermark(conn)? {
        merged.retain(|(file, _)| *file <= after);
        merged.extend(unposted(conn, tok, after)?);
        merged.sort_unstable_by_key(|(file, _)| *file);
    }
    Ok(merged)
}

/// Live document frequency: `vocab.df` adjusted by pending deltas.
pub fn effective_df(conn: &Connection, tok: i64) -> Result<u64> {
    let pending: bool = conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM post_delta WHERE tok=?1)")?
        .query_row([tok], |row| row.get(0))?;
    if !pending && cold_watermark(conn)?.is_none() {
        let df: Option<i64> = conn
            .prepare_cached("SELECT df FROM vocab WHERE id=?1")?
            .query_row([tok], |row| row.get(0))
            .optional()?;
        return Ok(df.unwrap_or(0).max(0) as u64);
    }
    Ok(read_postings(conn, tok)?.len() as u64)
}

/// Vocab ids of identifier tokens containing the trigram.
pub fn gram_tokens(conn: &Connection, gram: i64) -> Result<Vec<i64>> {
    let mut ids = gram_base(conn, gram)?;
    let mut select = conn.prepare_cached("SELECT tok FROM gram_delta WHERE g=?1")?;
    for id in select.query_map([gram], |row| row.get::<_, i64>(0))? {
        ids.push(id?);
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

pub(crate) fn base_postings(conn: &Connection, tok: i64) -> Result<Vec<(i64, u32)>> {
    let blob: Option<Vec<u8>> = conn
        .prepare_cached("SELECT postings FROM vocab_post WHERE tok=?1")?
        .query_row([tok], |row| row.get(0))
        .optional()?;
    blob.map_or(Ok(Vec::new()), |blob| varint::decode_pairs(&blob))
}

pub(crate) fn gram_base(conn: &Connection, gram: i64) -> Result<Vec<i64>> {
    let blob: Option<Option<Vec<u8>>> = conn
        .prepare_cached("SELECT toks FROM gram WHERE g=?1")?
        .query_row([gram], |row| row.get(0))
        .optional()?;
    blob.flatten()
        .map_or(Ok(Vec::new()), |blob| varint::decode_ids(&blob))
}

fn deltas(conn: &Connection, tok: i64) -> Result<Vec<(i64, i64)>> {
    let mut select =
        conn.prepare_cached("SELECT file, tf FROM post_delta WHERE tok=?1 ORDER BY file")?;
    let rows = select.query_map([tok], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Apply file-sorted deltas to file-sorted base postings.
pub(crate) fn apply_deltas(base: Vec<(i64, u32)>, deltas: &[(i64, i64)]) -> Vec<(i64, u32)> {
    if deltas.is_empty() {
        return base;
    }
    let mut out = Vec::with_capacity(base.len() + deltas.len());
    let mut pending = deltas.iter().peekable();
    let tf = |value: i64| u32::try_from(value).unwrap_or(u32::MAX);
    for (file, base_tf) in base {
        while let Some((delta_file, delta_tf)) = pending.next_if(|(f, _)| *f < file) {
            if *delta_tf > 0 {
                out.push((*delta_file, tf(*delta_tf)));
            }
        }
        match pending.next_if(|(f, _)| *f == file) {
            Some((_, delta_tf)) if *delta_tf > 0 => out.push((file, tf(*delta_tf))),
            Some(_) => {}
            None => out.push((file, base_tf)),
        }
    }
    out.extend(
        pending
            .filter(|(_, delta_tf)| *delta_tf > 0)
            .map(|(file, delta_tf)| (*file, tf(*delta_tf))),
    );
    out
}

/// The cold build's watermark while one is publishing.
fn cold_watermark(conn: &Connection) -> Result<Option<i64>> {
    let state: String = conn
        .prepare_cached("SELECT state_json FROM meta WHERE singleton=1")?
        .query_row([], |row| row.get(0))?;
    let parsed: serde_json::Value = serde_json::from_str(&state)
        .map_err(|_| crate::IndexError::Corrupt("meta.state_json is not JSON"))?;
    Ok(parsed
        .get("cold_posted_through")
        .and_then(serde_json::Value::as_i64))
}

fn unposted(conn: &Connection, tok: i64, after: i64) -> Result<Vec<(i64, u32)>> {
    let mut select =
        conn.prepare_cached("SELECT file, toks FROM file_tok WHERE file > ?1 ORDER BY file")?;
    let mut rows = select.query([after])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let file: i64 = row.get(0)?;
        let blob = row
            .get_ref(1)?
            .as_blob()
            .map_err(|_| crate::IndexError::Corrupt("file_tok is not a blob"))?;
        let pairs = varint::decode_pairs(blob)?;
        if let Ok(at) = pairs.binary_search_by_key(&tok, |(id, _)| *id) {
            out.push((file, pairs[at].1));
        }
    }
    Ok(out)
}
