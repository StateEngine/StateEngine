//! Walk scoped source files by path; only verified matches consume admission.
use super::*;
use rusqlite::{OptionalExtension, params};
pub(super) fn file_window(
    sql: &SqlView<'_>,
    started: bool,
    key: &[u8],
    scope: &SearchScope,
) -> AtlasResult<(Vec<FileRow>, bool)> {
    let previous: Option<String> = if started {
        Some(
            sql.prepare("SELECT path_key FROM files WHERE key=?1")?
                .query_row([key], |r| r.get(0))
                .optional()
                .map_err(cache_error)?
                .ok_or_else(|| {
                    cursor::invalid(
                        "the last source file moved out of this index; restart the search",
                    )
                })?,
        )
    } else {
        None
    };
    let query_sql = if started {
        format!(
            "SELECT {FILE_COLUMNS} FROM files f WHERE f.path_key>?1 AND atlas_scope(f.path,f.language,?2,?3) ORDER BY f.path_key LIMIT 33"
        )
    } else {
        format!(
            "SELECT {FILE_COLUMNS} FROM files f WHERE atlas_scope(f.path,f.language,?1,?2) ORDER BY f.path_key LIMIT 33"
        )
    };
    let mut statement = sql.prepare(&query_sql)?;
    let paths = scope.packed_paths();
    let languages = scope.packed_languages();
    let mut rows = if let Some(previous) = previous {
        statement.query(params![previous, paths, languages])
    } else {
        statement.query(params![paths, languages])
    }
    .map_err(cache_error)?;
    let mut files = Vec::with_capacity(33);
    while let Some(row) = rows.next().map_err(cache_error)? {
        files.push(file(row, 0)?);
    }
    let more = files.len() > 32;
    files.truncate(32);
    Ok((files, more))
}
