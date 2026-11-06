//! Atomic graph retirement, split so every prepared statement fits 16 KiB.
//! Call only inside CacheConnection::write's finite file transaction. File and
//! parent foreign keys remain enforced; they no longer expand one DELETE into
//! the entire graph's recursive cascade bytecode before it can be admitted.
use super::connection::SqlView;
use crate::{
    errors::{AtlasResult, cache_error},
    model::FileId,
};
use rusqlite::OptionalExtension;

/// Replacements keep the file row and discard its complete old semantic set.
/// Incoming candidates stay present as NameOnly, never resolved-to-NULL claims.
pub fn clear_semantics(sql: &SqlView<'_>, file_row: i64) -> AtlasResult<()> {
    super::reference_counts::incoming(sql, file_row)?;
    for statement in [
        "UPDATE refs SET accuracy='NameOnly',target=NULL
         WHERE target IN (SELECT id FROM symbols WHERE file=?1)",
        "UPDATE imports SET target_symbol=NULL,resolution='NameOnly'
         WHERE target_symbol IN (SELECT id FROM symbols WHERE file=?1)",
    ] {
        sql.prepare(statement)?
            .execute([file_row])
            .map_err(cache_error)?;
    }
    super::reference_counts::outgoing(sql, file_row)?;
    for statement in [
        "DELETE FROM refs WHERE file=?1",
        "DELETE FROM imports WHERE file=?1",
        // The self-parent FK checks at statement completion, after this whole
        // file's tree is gone. The small trigger deletes each exact FTS rowid.
        "DELETE FROM symbols WHERE file=?1",
    ] {
        sql.prepare(statement)?
            .execute([file_row])
            .map_err(cache_error)?;
    }
    Ok(())
}

/// A confirmed removal (or deliberate ignore change), never a source read
/// failure. False is an actually absent stable file key in this SQL snapshot.
pub fn delete_file(sql: &SqlView<'_>, file: FileId) -> AtlasResult<bool> {
    let row: Option<i64> = sql
        .prepare("SELECT id FROM files WHERE key=?1")?
        .query_row([file.0.as_slice()], |r| r.get(0))
        .optional()
        .map_err(cache_error)?;
    let Some(row) = row else { return Ok(false) };
    for statement in [
        "DELETE FROM touches WHERE target_kind='symbol' AND target_key IN (SELECT key FROM symbols WHERE file=?1)",
        "DELETE FROM activity WHERE target_kind='symbol' AND target_key IN (SELECT key FROM symbols WHERE file=?1)",
        "UPDATE mentions SET accuracy='NameOnly' WHERE target_kind='symbol' AND target_key IN (SELECT key FROM symbols WHERE file=?1)",
    ] {
        sql.prepare(statement)?
            .execute([row])
            .map_err(cache_error)?;
    }
    clear_semantics(sql, row)?;
    sql.prepare(
        "UPDATE mentions SET accuracy='NameOnly' WHERE target_kind='file' AND target_key=?1",
    )?
    .execute([file.0.as_slice()])
    .map_err(cache_error)?;
    sql.prepare("UPDATE imports SET target_file=NULL,target_symbol=NULL,resolution='NameOnly' WHERE target_file=?1")?
        .execute([row]).map_err(cache_error)?;
    sql.prepare("DELETE FROM files WHERE id=?1")?
        .execute([row])
        .map_err(cache_error)?;
    sql.prepare("DELETE FROM touches WHERE target_kind='file' AND target_key=?1")?
        .execute([file.0.as_slice()])
        .map_err(cache_error)?;
    sql.prepare("DELETE FROM activity WHERE target_kind='file' AND target_key=?1")?
        .execute([file.0.as_slice()])
        .map_err(cache_error)?;
    Ok(true)
}
