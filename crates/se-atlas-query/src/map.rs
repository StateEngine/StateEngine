//! A small orientation map of the indexed tree, from SQLite alone and inside
//! one snapshot: the largest areas by file count, and the files most other
//! files import, each with its first top-level declarations. Ordering is
//! fixed by counts then paths, so the same index always gives the same map.
use rusqlite::{Connection, ErrorCode, params};
use se_atlas_index::{
    IndexError, Result,
    extract::{SymbolKind, display_name, flags},
    store::Reader,
};
use std::{collections::BTreeMap, time::Instant};

/// Areas, hubs and declarations per hub a map lists at most.
pub const MAX_AREAS: usize = 8;
pub const MAX_HUBS: usize = 8;
pub const MAX_DECLARATIONS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Map {
    /// Indexed files, tests included.
    pub files: u64,
    /// `(area, files)`, largest first.
    pub areas: Vec<(String, u64)>,
    /// Areas left out by [`MAX_AREAS`].
    pub more_areas: u64,
    pub hubs: Vec<Hub>,
    /// More imported files exist than [`MAX_HUBS`] lists.
    pub more_hubs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hub {
    pub path: String,
    /// Distinct indexed files importing this one.
    pub importers: u64,
    pub declarations: Vec<String>,
}

/// The area of a path: its first directory, or its first two when the first
/// holds most of the tree, as a workspace of packages does.
fn area(path: &str, split: Option<&str>) -> String {
    let mut parts = path.split('/');
    let first = parts.next().unwrap_or(path);
    match (split, parts.next()) {
        (Some(split), Some(second)) if split == first && path.matches('/').count() >= 2 => {
            format!("{first}/{second}")
        }
        _ if path.contains('/') => first.to_owned(),
        _ => ".".to_owned(),
    }
}

/// The map, or `None` once `deadline` passes. SQLite is interrupted mid-query,
/// so a slow index never holds the caller past its deadline.
pub fn map(reader: &mut Reader, deadline: Instant) -> Result<Option<Map>> {
    reader.interrupt_at(Some(deadline))?;
    let built = reader
        .snapshot()
        .and_then(|snapshot| build(snapshot.connection()));
    reader.interrupt_at(None)?;
    match built {
        Err(IndexError::Sqlite(error))
            if error.sqlite_error_code() == Some(ErrorCode::OperationInterrupted) =>
        {
            Ok(None)
        }
        Ok(_) if Instant::now() >= deadline => Ok(None),
        built => built.map(Some),
    }
}

fn build(conn: &Connection) -> Result<Map> {
    let mut select = conn.prepare_cached("SELECT path, flags FROM files")?;
    let mut paths = Vec::new();
    for row in select.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<u32>>(1)?))
    })? {
        let (path, file_flags) = row?;
        let file_flags = file_flags.unwrap_or(0);
        if file_flags & (flags::TEST | flags::GENERATED | flags::BINARY) == 0 {
            paths.push(path);
        }
    }
    let files: i64 = conn.query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))?;
    let mut first: BTreeMap<&str, u64> = BTreeMap::new();
    for path in &paths {
        *first
            .entry(path.split('/').next().unwrap_or(path))
            .or_default() += 1;
    }
    let split = first
        .iter()
        .find(|(_, count)| **count * 2 > paths.len() as u64)
        .map(|(name, _)| *name);
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for path in &paths {
        *counts.entry(area(path, split)).or_default() += 1;
    }
    let mut areas: Vec<_> = counts.into_iter().collect();
    areas.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let more_areas = areas.len().saturating_sub(MAX_AREAS) as u64;
    areas.truncate(MAX_AREAS);

    let mut hubs = Vec::new();
    let mut ranked = conn.prepare_cached(
        "SELECT f.id, f.path, COUNT(DISTINCT i.file) AS n FROM imp i
         JOIN files f ON f.id = i.target_file
         WHERE i.target_file IS NOT NULL AND i.file != i.target_file
           AND COALESCE(f.flags, 0) & ?1 = 0
         GROUP BY i.target_file ORDER BY n DESC, f.path LIMIT ?2",
    )?;
    // Named declarations first; module, namespace, impl and test entries only
    // when a file declares nothing else, as a crate root often does.
    let mut declared = conn.prepare_cached(
        "SELECT v.tok, s.sig FROM sym s JOIN vocab v ON v.id = s.name
         WHERE s.file=?1 AND s.parent IS NULL
         ORDER BY COALESCE(s.kind, -1) IN (?3, ?4, ?5, ?6), s.line, s.id LIMIT ?2",
    )?;
    let grouping = [
        SymbolKind::Module,
        SymbolKind::Namespace,
        SymbolKind::Impl,
        SymbolKind::Test,
    ]
    .map(SymbolKind::code);
    let skip = flags::TEST | flags::GENERATED | flags::BINARY;
    // One row past the page tells whether hubs were left out.
    let rows = ranked.query_map(params![skip, MAX_HUBS as i64 + 1], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut more_hubs = false;
    for row in rows {
        let (id, path, importers) = row?;
        if hubs.len() == MAX_HUBS {
            more_hubs = true;
            break;
        }
        let names = declared.query_map(
            params![
                id,
                MAX_DECLARATIONS as i64,
                grouping[0],
                grouping[1],
                grouping[2],
                grouping[3]
            ],
            |row| {
                Ok(display_name(
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    &row.get::<_, String>(0)?,
                ))
            },
        )?;
        hubs.push(Hub {
            path,
            importers: importers.unsigned_abs(),
            declarations: names.collect::<rusqlite::Result<_>>()?,
        });
    }
    Ok(Map {
        files: files.unsigned_abs(),
        areas,
        more_areas,
        hubs,
        more_hubs,
    })
}
