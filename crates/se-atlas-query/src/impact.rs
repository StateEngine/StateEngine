//! What an edit to a target could affect, in sections read from one
//! snapshot and never from the disk:
//!
//! * callers: files that import a defining file through `imp_target` and
//!   hold the target's name, then their own importers up to `depth`, then
//!   files that only hold the name;
//! * covering tests, from `covers_target`, keeping how each covers it;
//! * project-visible records that mention the target;
//! * recent changes to the target, from `changes` and `touches`.
//!
//! Past the soft deadline the sections gathered so far come back with
//! `deadline_reached` set; impact never fails for running out of time.
use super::{
    Answer, Section, SymbolRef, Target, TargetOf, importers, name_postings,
    target::{FileRef, resolve_in},
};
use rusqlite::params;
use se_atlas_index::{
    Result,
    extract::covers::CoverHow,
    store::{ReadSnapshot, Reader},
};
use se_atlas_search::{Budget, DEFAULT_DEADLINE};
use std::{cmp::Reverse, collections::HashSet, time::Duration};

pub const MAX_CALLERS: usize = 30;
pub const MAX_TESTS: usize = 20;
pub const MAX_RECORDS: usize = 10;
pub const MAX_CHANGES: usize = 5;
pub const DEFAULT_DEPTH: u32 = 2;
pub const MAX_DEPTH: u32 = 8;
/// Files the reverse import walk visits before it stops counting.
const MAX_WALK: usize = 10_000;
/// History rows read per defining file, newest first.
const MAX_SCANNED_CHANGES: usize = 64;

#[derive(Clone, Debug)]
pub struct ImpactRequest {
    pub target: Target,
    /// Reverse import levels, 1 to [`MAX_DEPTH`]; zero means the default.
    pub depth: u32,
    pub deadline: Duration,
}

impl ImpactRequest {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            depth: DEFAULT_DEPTH,
            deadline: DEFAULT_DEADLINE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerVia {
    /// Imports a defining file (and holds the name, for a symbol).
    Imports,
    /// Imports a caller, `depth` levels from the target.
    Dependent,
    /// Holds the name without importing a defining file.
    NameOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub path: String,
    pub depth: u32,
    pub via: CallerVia,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoveringTest {
    pub path: String,
    pub how: Option<CoverHow>,
    /// Covered through a shared test helper's import.
    pub via_helper: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedRecord {
    pub record_id: String,
    pub kind: String,
    pub title: String,
    pub occurred_unix_ms: i64,
    pub accuracy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentChange {
    pub at_unix_ms: i64,
    /// A `changes` kind, or a touch kind.
    pub kind: String,
    pub path: Option<String>,
    pub symbol: Option<String>,
    /// Set for index changes.
    pub generation: Option<i64>,
    /// Set for touches.
    pub actor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Impact {
    /// The defining files.
    pub files: Vec<FileRef>,
    pub symbols: Vec<SymbolRef>,
    /// The name has more definitions than `symbols` lists; see
    /// [`super::target::MAX_DEFINITIONS`].
    pub definitions_capped: bool,
    pub callers: Section<Caller>,
    pub tests: Section<CoveringTest>,
    pub records: Section<LinkedRecord>,
    /// Restricted records that mention the target, not listed here.
    pub restricted_records: usize,
    pub changes: Section<RecentChange>,
    pub deadline_reached: bool,
}

/// Gather the impact of editing the target.
pub fn impact(reader: &Reader, request: &ImpactRequest) -> Result<Answer<Impact>> {
    let budget = Budget::start(request.deadline);
    let snapshot = reader.snapshot()?;
    let target = match Answer::unresolved(resolve_in(&snapshot, &request.target)?) {
        Ok(target) => target,
        Err(answer) => return Ok(answer),
    };
    let depth = match request.depth {
        0 => DEFAULT_DEPTH,
        n => n.min(MAX_DEPTH),
    };
    let files: Vec<FileRef> = target.files().into_iter().cloned().collect();
    let mut out = Impact {
        symbols: target.symbols().to_vec(),
        definitions_capped: target.capped(),
        files,
        callers: Section::default(),
        tests: Section::default(),
        records: Section::default(),
        restricted_records: 0,
        changes: Section::default(),
        deadline_reached: false,
    };
    let postings = name_postings(&snapshot, &target)?;
    // Each section starts only while time remains.
    let on_time = |out: &mut Impact| {
        out.deadline_reached |= budget.expired();
        !out.deadline_reached
    };
    let mut test_ids = HashSet::new();
    if on_time(&mut out) {
        let tests = covering_tests(&snapshot, &out.files, &postings)?;
        test_ids.extend(tests.iter().map(|(id, _)| *id));
        out.tests = Section::capped(tests.into_iter().map(|(_, test)| test).collect(), MAX_TESTS);
    }
    if on_time(&mut out) {
        callers(
            &snapshot, &target, &postings, &test_ids, depth, &budget, &mut out,
        )?;
    }
    if on_time(&mut out) {
        records(&snapshot, &target, &mut out)?;
    }
    if on_time(&mut out) {
        out.changes = recent_changes(&snapshot, &target)?;
    }
    Ok(Answer::Found(out))
}

/// Tests covering any defining file; for a symbol, tests that hold its
/// name first. Returns `(test file id, test)`.
fn covering_tests(
    snapshot: &ReadSnapshot<'_>,
    files: &[FileRef],
    postings: &HashSet<i64>,
) -> Result<Vec<(i64, CoveringTest)>> {
    let mut select = snapshot.connection().prepare_cached(
        "SELECT c.test_file, f.path, c.how, c.via_helper FROM covers c
         JOIN files f ON f.id = c.test_file WHERE c.target_file=?1",
    )?;
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for file in files {
        let rows = select.query_map([file.id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        for row in rows {
            let (id, path, how, via_helper) = row?;
            if seen.insert(id) {
                let names = postings.is_empty() || postings.contains(&id);
                found.push((!names, how, via_helper, path, id));
            }
        }
    }
    found.sort();
    Ok(found
        .into_iter()
        .map(|(_, how, via_helper, path, id)| {
            let test = CoveringTest {
                path,
                how: cover_how(how),
                via_helper,
            };
            (id, test)
        })
        .collect())
}

/// The cover kind stored as `covers.how`.
pub(crate) fn cover_how(code: i64) -> Option<CoverHow> {
    [CoverHow::Import, CoverHow::Inline, CoverHow::Name]
        .into_iter()
        .find(|how| *how as i64 == code)
}

/// Callers by reverse import level, then name-only holders of a symbol.
/// Covering tests are listed as tests, not again as callers.
fn callers(
    snapshot: &ReadSnapshot<'_>,
    target: &TargetOf,
    postings: &HashSet<i64>,
    tests: &HashSet<i64>,
    depth: u32,
    budget: &Budget,
    out: &mut Impact,
) -> Result<()> {
    let symbol = !target.symbols().is_empty();
    let mut seen: HashSet<i64> = out.files.iter().map(|file| file.id).collect();
    let mut frontier: Vec<i64> = out.files.iter().map(|file| file.id).collect();
    let mut found: Vec<(u32, CallerVia, i64)> = Vec::new();
    for level in 1..=depth {
        let mut next = Vec::new();
        for file in std::mem::take(&mut frontier) {
            if budget.expired() {
                out.deadline_reached = true;
                break;
            }
            for importer in importers(snapshot, file)? {
                let names = !symbol || level > 1 || postings.contains(&importer);
                if names && seen.insert(importer) {
                    next.push(importer);
                }
            }
        }
        let via = if level == 1 {
            CallerVia::Imports
        } else {
            CallerVia::Dependent
        };
        next.sort_unstable();
        found.extend(next.iter().map(|file| (level, via, *file)));
        if found.len() >= MAX_WALK || out.deadline_reached {
            out.callers.more_is_floor = found.len() >= MAX_WALK;
            break;
        }
        frontier = next;
    }
    // Past the deadline the walk left importers unvisited; they must not
    // be mistaken for files that only hold the name.
    if symbol && !out.deadline_reached {
        let mut name_only: Vec<i64> = postings
            .iter()
            .copied()
            .filter(|file| !seen.contains(file))
            .collect();
        name_only.sort_unstable();
        found.extend(
            name_only
                .into_iter()
                .map(|file| (1, CallerVia::NameOnly, file)),
        );
    }
    found.retain(|(_, _, file)| !tests.contains(file));
    let more = found.len().saturating_sub(MAX_CALLERS);
    let mut path_of = snapshot
        .connection()
        .prepare_cached("SELECT path FROM files WHERE id=?1")?;
    let mut items = Vec::with_capacity(found.len().min(MAX_CALLERS));
    for (depth, via, file) in found.into_iter().take(MAX_CALLERS) {
        let path = path_of.query_row([file], |row| row.get(0))?;
        items.push(Caller { path, depth, via });
    }
    out.callers.items = items;
    out.callers.more = more;
    Ok(())
}

/// The `(target_kind, target_key)` pairs history and records use.
pub(crate) fn keys(target: &TargetOf) -> Vec<(&'static str, &[u8])> {
    let mut keys: Vec<(&'static str, &[u8])> = target
        .files()
        .into_iter()
        .map(|file| ("file", file.key.as_slice()))
        .collect();
    keys.extend(
        target
            .symbols()
            .iter()
            .map(|symbol| ("symbol", symbol.key.as_slice())),
    );
    keys
}

/// Project-visible records mentioning the target, newest first. Restricted
/// records are only counted: their audience is checked by the record store.
fn records(snapshot: &ReadSnapshot<'_>, target: &TargetOf, out: &mut Impact) -> Result<()> {
    let mut select = snapshot.connection().prepare_cached(
        "SELECT r.record_id, r.kind, r.title, r.occurred_unix_ms, m.accuracy, r.visibility
         FROM mentions m JOIN records r ON r.id = m.source_id
         WHERE m.target_kind=?1 AND m.target_key=?2 AND m.source_kind='record'",
    )?;
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for (kind, key) in keys(target) {
        let rows = select.query_map(params![kind, key], |row| {
            Ok((
                row.get::<_, String>(5)?,
                LinkedRecord {
                    record_id: row.get(0)?,
                    kind: row.get(1)?,
                    title: row.get(2)?,
                    occurred_unix_ms: row.get(3)?,
                    accuracy: row.get(4)?,
                },
            ))
        })?;
        for row in rows {
            let (visibility, record) = row?;
            if !seen.insert(record.record_id.clone()) {
                continue;
            }
            if visibility == "project" {
                found.push(record);
            } else {
                out.restricted_records += 1;
            }
        }
    }
    found.sort_by(|a, b| {
        b.occurred_unix_ms
            .cmp(&a.occurred_unix_ms)
            .then_with(|| a.record_id.cmp(&b.record_id))
    });
    out.records = Section::capped(found, MAX_RECORDS);
    Ok(())
}

/// Index changes to a defining file (file-level rows, and for a symbol its
/// own rows) and project-visible touches of the target, newest first. Each
/// source reads at most [`MAX_SCANNED_CHANGES`] rows; an indexed count
/// covers the rest, and where their relevance is unknown `more` is a floor.
/// Touches from restricted records are never read.
pub(crate) fn recent_changes(
    snapshot: &ReadSnapshot<'_>,
    target: &TargetOf,
) -> Result<Section<RecentChange>> {
    let conn = snapshot.connection();
    let wanted: HashSet<&[u8]> = target
        .symbols()
        .iter()
        .map(|symbol| symbol.key.as_slice())
        .collect();
    let scan = MAX_SCANNED_CHANGES as i64;
    let mut changes = conn.prepare_cached(
        "SELECT c.generation, g.observed_unix_ms, c.kind, c.path, c.pointer_json, c.symbol_key,
           c.ordinal
         FROM changes c JOIN generations g ON g.generation = c.generation
         WHERE c.file_key=?1 ORDER BY c.generation DESC, c.ordinal DESC LIMIT ?2",
    )?;
    let mut count_changes =
        conn.prepare_cached("SELECT count(*) FROM changes WHERE file_key=?1")?;
    let (mut found, mut unread, mut floor) = (Vec::new(), 0usize, false);
    for file in target.files() {
        let rows = changes.query_map(params![file.key.as_slice(), scan], |row| {
            let change = RecentChange {
                generation: Some(row.get(0)?),
                at_unix_ms: row.get(1)?,
                kind: row.get(2)?,
                path: row.get(3)?,
                // The pointer's JSON until the page is cut; see below.
                symbol: row.get::<_, Option<String>>(4)?,
                actor: None,
            };
            Ok((
                change,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut read = 0usize;
        for row in rows {
            let (change, symbol_key, ordinal) = row?;
            read += 1;
            let relevant =
                symbol_key.is_none_or(|key| wanted.is_empty() || wanted.contains(key.as_slice()));
            if relevant {
                found.push((change, ordinal));
            }
        }
        if read == MAX_SCANNED_CHANGES {
            let rest =
                count(&mut count_changes, params![file.key.as_slice()])?.saturating_sub(read);
            // A file target wants every row; a symbol's rows are unknown.
            if wanted.is_empty() {
                unread += rest;
            } else {
                floor |= rest > 0;
            }
        }
    }
    let mut touches = conn.prepare_cached(
        "SELECT at_unix_ms, touch_kind, actor FROM touches
         WHERE target_kind=?1 AND target_key=?2 AND restricted_record IS NULL
         ORDER BY at_unix_ms DESC LIMIT ?3",
    )?;
    let mut count_touches = conn.prepare_cached(
        "SELECT count(*) FROM touches
         WHERE target_kind=?1 AND target_key=?2 AND restricted_record IS NULL",
    )?;
    for (kind, key) in keys(target) {
        let rows = touches.query_map(params![kind, key, scan], |row| {
            let touch = RecentChange {
                at_unix_ms: row.get(0)?,
                kind: row.get(1)?,
                actor: row.get(2)?,
                path: None,
                symbol: None,
                generation: None,
            };
            Ok((touch, 0))
        })?;
        let before = found.len();
        for row in rows {
            found.push(row?);
        }
        if found.len() - before == MAX_SCANNED_CHANGES {
            unread +=
                count(&mut count_touches, params![kind, key])?.saturating_sub(MAX_SCANNED_CHANGES);
        }
    }
    found.sort_by_key(|(change, ordinal)| {
        (
            Reverse(change.at_unix_ms),
            Reverse(change.generation),
            *ordinal,
        )
    });
    let mut section = Section::capped(
        found.into_iter().map(|(change, _)| change).collect(),
        MAX_CHANGES,
    );
    section.more += unread;
    section.more_is_floor = floor;
    for change in &mut section.items {
        change.symbol = change.symbol.as_deref().and_then(pointer_name);
    }
    Ok(section)
}

fn count(
    select: &mut rusqlite::CachedStatement<'_>,
    params: impl rusqlite::Params,
) -> Result<usize> {
    let n: i64 = select.query_row(params, |row| row.get(0))?;
    Ok(usize::try_from(n).unwrap_or(0))
}

fn pointer_name(json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()?
        .get("name")?
        .as_str()
        .map(str::to_owned)
}
