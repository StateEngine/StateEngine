//! A file's symbol hierarchy, read from `sym` in one snapshot. A symbol
//! target outlines that symbol and everything nested inside it.
use super::{Answer, FileRef, Target, TargetOf, page_limit, target::resolve_in};
use se_atlas_index::{
    Result,
    extract::{Accuracy, SymbolKind, display_name, flags},
    store::Reader,
};
use std::collections::HashMap;

pub const DEFAULT_LIMIT: usize = 300;
pub const MAX_LIMIT: usize = 2_000;

#[derive(Clone, Debug)]
pub struct OutlineRequest {
    pub target: Target,
    /// Entries per answer, at most [`MAX_LIMIT`]; zero means the default.
    pub limit: usize,
}

impl OutlineRequest {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            limit: DEFAULT_LIMIT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutlineEntry {
    pub id: i64,
    pub name: String,
    pub kind: Option<SymbolKind>,
    pub line: u32,
    pub end_line: u32,
    pub accuracy: Accuracy,
    pub exported: bool,
    pub sig: Option<String>,
    /// The enclosing symbol's id.
    pub parent: Option<i64>,
    /// Nesting below the outline's top level, for indentation.
    pub depth: u32,
}

/// Why an outline may be missing symbols the file declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incomplete {
    /// The file looks binary; nothing was outlined.
    Binary,
    /// Minified or too large: only leading tokens were indexed, no outline.
    Minified,
    /// The per-file symbol cap was reached.
    Truncated,
    /// Extraction failed on this file.
    ExtractFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outline {
    pub file: FileRef,
    /// Depth-first, siblings in line order.
    pub entries: Vec<OutlineEntry>,
    /// Entries past the limit.
    pub omitted: usize,
    /// Set when the file's own flags say the outline is partial.
    pub incomplete: Option<Incomplete>,
}

/// Outline the target: a file, or the first definition of a symbol.
pub fn outline(reader: &Reader, request: &OutlineRequest) -> Result<Answer<Outline>> {
    let snapshot = reader.snapshot()?;
    let target = match Answer::unresolved(resolve_in(&snapshot, &request.target)?) {
        Ok(target) => target,
        Err(answer) => return Ok(answer),
    };
    let (file, root) = match target {
        TargetOf::File(file) => (file, None),
        TargetOf::Symbols { mut symbols, .. } => {
            let symbol = symbols.swap_remove(0);
            (symbol.file, Some(symbol.id))
        }
    };
    let rows = rows(snapshot.connection(), file.id)?;
    let ordered = depth_first(rows, root);
    let limit = page_limit(request.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let omitted = ordered.len().saturating_sub(limit);
    let mut entries = ordered;
    entries.truncate(limit);
    Ok(Answer::Found(Outline {
        incomplete: incomplete(file.flags),
        file,
        entries,
        omitted,
    }))
}

fn incomplete(file_flags: u32) -> Option<Incomplete> {
    if file_flags & flags::BINARY != 0 {
        Some(Incomplete::Binary)
    } else if file_flags & flags::EXTRACT_FAILED != 0 {
        Some(Incomplete::ExtractFailed)
    } else if file_flags & flags::MINIFIED != 0 {
        Some(Incomplete::Minified)
    } else if file_flags & flags::TRUNCATED != 0 {
        Some(Incomplete::Truncated)
    } else {
        None
    }
}

fn rows(conn: &rusqlite::Connection, file: i64) -> Result<Vec<OutlineEntry>> {
    let mut select = conn.prepare_cached(
        "SELECT s.id, s.parent, v.tok, s.kind, s.line, s.end_line, s.accuracy, s.exported, s.sig
         FROM sym s JOIN vocab v ON v.id = s.name WHERE s.file=?1 ORDER BY s.line, s.id",
    )?;
    let rows = select.query_map([file], |row| {
        let lower: String = row.get(2)?;
        let sig: Option<String> = row.get(8)?;
        Ok(OutlineEntry {
            id: row.get(0)?,
            parent: row.get(1)?,
            name: display_name(sig.as_deref(), &lower),
            kind: row
                .get::<_, Option<i64>>(3)?
                .and_then(SymbolKind::from_code),
            line: row.get::<_, Option<u32>>(4)?.unwrap_or(0),
            end_line: row.get::<_, Option<u32>>(5)?.unwrap_or(0),
            accuracy: match row.get::<_, Option<i64>>(6)? {
                Some(code) if code == Accuracy::Syntactic as i64 => Accuracy::Syntactic,
                _ => Accuracy::Heuristic,
            },
            exported: row.get::<_, Option<bool>>(7)?.unwrap_or(false),
            sig,
            depth: 0,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Order line-sorted rows depth-first. With `root`, keep only that symbol
/// and its descendants. A parent outside the file, or a parent chain that
/// loops, makes a symbol top-level rather than dropping it.
fn depth_first(rows: Vec<OutlineEntry>, root: Option<i64>) -> Vec<OutlineEntry> {
    let index: HashMap<i64, usize> = rows.iter().enumerate().map(|(at, e)| (e.id, at)).collect();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); rows.len()];
    let mut tops = Vec::new();
    for (at, entry) in rows.iter().enumerate() {
        match entry.parent.and_then(|parent| index.get(&parent)) {
            Some(&parent) if parent != at => children[parent].push(at),
            _ => tops.push(at),
        }
    }
    let starts = match root.and_then(|id| index.get(&id)) {
        Some(&at) => vec![at],
        None if root.is_some() => Vec::new(),
        None => tops,
    };
    let mut placed = vec![false; rows.len()];
    let mut order = Vec::with_capacity(rows.len());
    let mut stack: Vec<(usize, u32)> = starts.into_iter().rev().map(|at| (at, 0)).collect();
    while let Some((at, depth)) = stack.pop() {
        if std::mem::replace(&mut placed[at], true) {
            continue;
        }
        order.push((at, depth));
        stack.extend(children[at].iter().rev().map(|child| (*child, depth + 1)));
    }
    if root.is_none() {
        // Symbols on a parent loop were never reached from a top.
        order.extend((0..rows.len()).filter(|at| !placed[*at]).map(|at| (at, 0)));
    }
    let mut slots: Vec<Option<OutlineEntry>> = rows.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|(at, depth)| {
            slots[at].take().map(|mut entry| {
                entry.depth = depth;
                entry
            })
        })
        .collect()
}
