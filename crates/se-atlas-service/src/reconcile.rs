//! Find what changed while nothing was watching: compare each discovered
//! file's size and modification time, read through custody without reading
//! its bytes, against what the store last indexed. New, changed and vanished
//! paths come back; the writer re-indexes only those.
use se_atlas_index::{
    Result,
    custody::{GuardedOpen, IndexSourceRoot},
    store::Store,
};
use std::collections::HashMap;

/// Root-relative paths whose index rows may be stale, sorted.
pub(crate) fn changed(
    store: &Store,
    source: &IndexSourceRoot,
    discovered: &[String],
) -> Result<Vec<String>> {
    let mut indexed: HashMap<String, (i64, i64)> = HashMap::new();
    {
        let mut select = store
            .connection()
            .prepare_cached("SELECT path, coalesce(size, -1), coalesce(mtime_ns, -1) FROM files")?;
        let rows = select.query_map([], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?))))?;
        for row in rows {
            let (path, facts) = row?;
            indexed.insert(path, facts);
        }
    }
    let mut out = Vec::new();
    for path in discovered {
        match indexed.remove(path) {
            None => out.push(path.clone()),
            Some(facts) if stat(source, path)? != Some(facts) => out.push(path.clone()),
            Some(_) => {}
        }
    }
    out.extend(indexed.into_keys());
    out.sort_unstable();
    Ok(out)
}

/// Indexed files below `directory`. A watcher that cannot tell a removed
/// directory from a removed file reports the name alone; its files go too.
pub(crate) fn under(store: &Store, directory: &str) -> Result<Vec<String>> {
    // '0' sorts right after '/', so this range is exactly `directory/...`.
    let mut select = store
        .connection()
        .prepare_cached("SELECT path FROM files WHERE path > ?1 || '/' AND path < ?1 || '0'")?;
    let rows = select.query_map([directory], |row| row.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Size and modification time as the store records them, `None` when the
/// name no longer denotes a readable regular file.
pub(crate) fn stat(source: &IndexSourceRoot, path: &str) -> Result<Option<(i64, i64)>> {
    Ok(match source.open_guarded_file(path)? {
        GuardedOpen::File(file) => {
            let revision = file.opened_revision();
            Some((
                i64::try_from(revision.size).unwrap_or(i64::MAX),
                i64::try_from(revision.mtime_unix_nanos).unwrap_or(i64::MAX),
            ))
        }
        GuardedOpen::Absent | GuardedOpen::Denied | GuardedOpen::Refused => None,
    })
}
