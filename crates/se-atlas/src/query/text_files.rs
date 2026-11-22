//! Walk scoped source files by path; only verified matches consume admission.
use super::*;
use rusqlite::{OptionalExtension, params};
pub(super) fn file_window(
    sql: &SqlView<'_>,
    started: bool,
    key: &[u8],
    last_path_key: &mut Option<String>,
    scope: &SearchScope,
) -> AtlasResult<(Vec<FileRow>, bool)> {
    if started && last_path_key.is_none() {
        *last_path_key = Some(
            sql.prepare("SELECT path_key FROM files WHERE key=?1")?
                .query_row([key], |r| r.get(0))
                .optional()
                .map_err(cache_error)?
                .ok_or_else(|| {
                    cursor::invalid(
                        "the last source file moved out of this index; restart the search",
                    )
                })?,
        );
    }
    let filter = if started { "f.path_key>?3 AND " } else { "" };
    let mut statement = sql.prepare(&format!(
        "SELECT {FILE_COLUMNS},f.path_key FROM files f WHERE {filter}atlas_scope(f.path,f.language,?1,?2) ORDER BY f.path_key LIMIT 257"
    ))?;
    let (paths, languages) = (scope.packed_paths(), scope.packed_languages());
    let mut rows = if let Some(previous) = last_path_key.as_deref() {
        statement.query(params![paths, languages, previous])
    } else {
        statement.query(params![paths, languages])
    }
    .map_err(cache_error)?;
    let mut files = Vec::with_capacity(256);
    let mut more = false;
    while let Some(row) = rows.next().map_err(cache_error)? {
        if files.len() == 256 {
            more = true;
            break;
        }
        *last_path_key = Some(get(row, 6)?);
        files.push(file(row, 0)?);
    }
    Ok((files, more))
}
