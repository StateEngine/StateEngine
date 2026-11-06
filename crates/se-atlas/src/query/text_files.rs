//! Walk scoped source files by path; only verified matches consume admission.
use super::*;
use rusqlite::{OptionalExtension, params};
pub(super) struct FileCandidate {
    pub id: i64,
    pub last: Option<i64>,
    pub key: [u8; 16],
}
pub(super) fn file_window(
    sql: &SqlView<'_>,
    started: bool,
    key: &[u8],
    scope: &SearchScope,
) -> AtlasResult<(Vec<FileCandidate>, bool)> {
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
    let mut statement=sql.prepare(if started {
        "SELECT id,key FROM files WHERE path_key>?1 AND atlas_scope(path,language,?2,?3) ORDER BY path_key LIMIT 33"
    } else {"SELECT id,key FROM files WHERE atlas_scope(path,language,?1,?2) ORDER BY path_key LIMIT 33"})?;
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
        files.push(FileCandidate {
            id: get(row, 0)?,
            last: None,
            key: blob(row, 1)?,
        });
    }
    let more = files.len() > 32;
    files.truncate(32);
    Ok((files, more))
}
