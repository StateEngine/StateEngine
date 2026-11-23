//! `refs` and `impact` on the wire. A private path and an unindexed name are
//! different answers. A file the watcher reported changed or removed is
//! marked stale or left out, and an answer read while changes are pending
//! is never complete: the index may not list what the edit added.
use super::{
    Examined, PageFacts, answer, checked, cursor, envelope, file_id, page, pointer, records, size,
    unknown,
};
use crate::{
    dirty::Change,
    error::index_error,
    read::{RecordCheck, STARTING},
    root::{Dirty, Shared},
};
use se_atlas_index::extract::covers::CoverHow;
use se_atlas_query::{
    Answer as Found, Target,
    impact::{CallerVia, ImpactRequest},
    refs::{RefAccuracy, RefGroup, RefLine, RefsRequest},
};
use se_types::code::AtlasText as _;
use se_types::{
    Page, Read, Result, SeError,
    code::{
        Accuracy, Answer, AtlasCursor, AtlasTarget, CodePointer, CoverageReason, Dependent,
        FileImpactHop, Impact, ImpactQuery, IndexSummary, Reference, ReferenceHit, ReferenceKind,
        RefsQuery, SnapshotFreshness, SymbolId, SymbolSelector,
    },
};

pub(crate) fn target(target: &AtlasTarget) -> Result<Target> {
    Ok(match target {
        AtlasTarget::Symbol(SymbolSelector::Name { name, .. }) => {
            Target::Symbol(name.as_str().to_owned())
        }
        AtlasTarget::Symbol(SymbolSelector::At { path, position }) => {
            Target::Auto(format!("{}:{}", path.as_str(), position.line))
        }
        AtlasTarget::File(path) => Target::File(path.as_str().to_owned()),
        AtlasTarget::Auto(text) => Target::Auto(text.as_str().to_owned()),
        AtlasTarget::Symbol(SymbolSelector::Id(_))
        | AtlasTarget::Commit(_)
        | AtlasTarget::Record(_) => {
            return Err(SeError::invalid(
                "Atlas target",
                "a path, path:line or symbol name",
            ));
        }
    })
}

/// The answer for a target that resolved to nothing usable.
pub(crate) fn unresolved<T, U>(
    index: &IndexSummary,
    found: Found<U>,
    asked: &AtlasTarget,
) -> Result<std::result::Result<U, Answer<Read<T>>>> {
    match found {
        Found::Found(value) => Ok(Ok(value)),
        Found::Refused { path } => Ok(Err(unknown(index, &refused(&path)))),
        Found::NotFound { suggestions } => {
            let hint = if suggestions.is_empty() {
                String::new()
            } else {
                format!("; did you mean: {}", suggestions.join(", "))
            };
            if matches!(asked, AtlasTarget::Auto(_)) && index.negative_complete() {
                return Err(SeError::invalid(
                    "Atlas target",
                    &format!("an indexed path, path:line or exact symbol name{hint}"),
                ));
            }
            Ok(Err(unknown(
                index,
                &format!("target not indexed; search by name or path and inspect coverage{hint}"),
            )))
        }
    }
}

/// The refusal for a path Atlas never reads.
pub(crate) fn refused(path: &str) -> String {
    format!(
        "{path} is a private file Atlas never reads or indexes; open it directly if you need it"
    )
}

/// How a listed file stands against the dirty paths: `None` when it was
/// removed and must not be listed.
fn freshness(dirty: &Dirty, path: &str) -> Option<SnapshotFreshness> {
    match dirty.change(path) {
        None => Some(SnapshotFreshness::Current),
        Some(Change::Modified) => Some(SnapshotFreshness::Stale),
        Some(Change::Removed) => None,
    }
}

pub(crate) fn refs(
    shared: &Shared,
    index: &IndexSummary,
    dirty: &Dirty,
    query: &RefsQuery,
) -> Result<Answer<Read<Page<ReferenceHit>>>> {
    let Some(source) = shared.source() else {
        return Ok(unknown(index, STARTING));
    };
    let (start, start_lines) = match &query.next {
        Some(next) => {
            let (file, lines) = position(next)?;
            (Some(file), lines)
        }
        None => (None, 0),
    };
    let request = RefsRequest {
        target: target(&query.target)?,
        limit: usize::from(query.budget.max_results),
        cursor: start,
        cursor_lines: start_lines,
        deadline: query.budget.work,
    };
    let found = shared.with_reader(|reader| {
        se_atlas_query::refs::refs(reader, source, &request).map_err(|e| index_error(&e))
    })?;
    let refs = match unresolved(index, found, &query.target)? {
        Ok(refs) => refs,
        Err(answer) => return Ok(answer),
    };
    let resolved = match refs.definitions.as_slice() {
        [only] => super::hash(Some(only.key.clone())).map(SymbolId),
        _ => None,
    };
    let pending = !dirty.paths.is_empty() || dirty.overflowed;
    let partial = refs.deadline_reached
        || refs.files_read_failed > 0
        || refs.files_partly_read > 0
        || pending;
    let mut index = index.clone();
    if refs.deadline_reached {
        index.note(CoverageReason::TimeLimit);
    }
    if pending {
        index.note(CoverageReason::StaleSnapshot);
    }
    let facts = |next, deadline, bytes| PageFacts {
        index: &index,
        budget: query.budget,
        after: query.next.as_ref(),
        next,
        examined: Examined::of(partial, deadline),
        bytes,
    };
    // Sized with the widest cursor, so a page that gains one still fits.
    let widest = wrap_position(usize::MAX, usize::MAX)?;
    let mut bytes = envelope::<ReferenceHit>(facts(Some(widest), refs.deadline_reached, 0))?;
    let max_bytes = query.budget.max_bytes as usize;
    let mut items = Vec::new();
    // The listed line the page ends on once the item or byte limit cuts it.
    let mut cut = None;
    let mut last = None;
    'groups: for (group_at, group) in refs.groups.iter().enumerate() {
        let Some((accuracy, fresh)) = listed(group, dirty, query.include_name_only) else {
            continue;
        };
        for (line_at, line) in group.lines.iter().enumerate() {
            let hit = reference(&group.path, line, fresh, accuracy, resolved)?;
            let cost = size(&hit) + 1;
            if items.is_empty() && bytes + cost > max_bytes {
                return Err(records::over_budget(bytes + cost, query.budget.max_bytes));
            }
            if items.len() >= usize::from(query.budget.max_results) || bytes + cost > max_bytes {
                cut = last;
                break 'groups;
            }
            bytes += cost;
            items.push(hit);
            last = Some((group_at, line_at));
        }
    }
    let next = match cut {
        Some((group, line)) => refs.resume_after(group, line),
        // Omit a non-progressing cursor when the deadline hit before the first resumed file.
        None => refs
            .next_cursor
            .map(|file| (file, refs.next_lines))
            .filter(|&(file, lines)| start != Some(file) || start_lines != lines),
    };
    let next = next
        .map(|(file, lines)| wrap_position(file, lines))
        .transpose()?;
    let deadline = refs.deadline_reached && cut.is_none();
    let value = page(items, facts(next, deadline, bytes))?;
    checked(answer(&index, Read::Present { value }), query.budget)
}

/// How a group's lines are listed, or `None` when they are left out: a
/// name-only match the query did not ask for, or a file since removed.
fn listed(
    group: &RefGroup,
    dirty: &Dirty,
    include_name_only: bool,
) -> Option<(Accuracy, SnapshotFreshness)> {
    let accuracy = match group.accuracy {
        RefAccuracy::ImportedFile => Accuracy::ImportedFile,
        RefAccuracy::NameOnly if include_name_only => Accuracy::NameOnly,
        RefAccuracy::NameOnly => return None,
    };
    Some((accuracy, freshness(dirty, &group.path)?))
}

fn reference(
    path: &str,
    line: &RefLine,
    fresh: SnapshotFreshness,
    accuracy: Accuracy,
    resolved: Option<SymbolId>,
) -> Result<ReferenceHit> {
    let text = line.text.trim_start();
    let import = ["use ", "import ", "from ", "#include", "require("]
        .iter()
        .any(|lead| text.starts_with(lead));
    Ok(ReferenceHit::Code(Reference {
        site: pointer(path, Some((line.line, line.line)), None, fresh)?,
        kind: if import {
            ReferenceKind::Import
        } else {
            ReferenceKind::ValueUse
        },
        spelling: line.text.clone(),
        enclosing: None,
        resolved_target: resolved,
        accuracy,
    }))
}

/// A refs page cursor: the candidate file the next page starts at and the
/// reference lines of that file already listed.
fn wrap_position(file: usize, lines: usize) -> Result<AtlasCursor> {
    cursor::wrap('r', &format!("{file}.{lines}"))
}

/// The position a refs cursor names; a cursor without a line count starts
/// at the beginning of its file.
fn position(next: &AtlasCursor) -> Result<(usize, usize)> {
    let text = cursor::unwrap('r', next)?;
    let (file, lines) = text.split_once('.').unwrap_or((text.as_str(), "0"));
    match (file.parse(), lines.parse()) {
        (Ok(file), Ok(lines)) => Ok((file, lines)),
        _ => Err(SeError::invalid(
            "Atlas cursor",
            "a cursor this query returned; repeat the query without it",
        )),
    }
}

pub(crate) fn impact(
    shared: &Shared,
    index: &IndexSummary,
    dirty: &Dirty,
    query: &ImpactQuery,
    checker: &dyn RecordCheck,
) -> Result<Answer<Read<Impact>>> {
    let request = ImpactRequest {
        target: target(&query.target)?,
        depth: u32::from(query.depth),
        deadline: query.budget.work,
    };
    let found = shared.with_reader(|reader| {
        se_atlas_query::impact::impact(reader, &request).map_err(|e| index_error(&e))
    })?;
    let found = match unresolved(index, found, &query.target)? {
        Ok(found) => found,
        Err(answer) => return Ok(answer),
    };
    let defining = found.files.first().map(|file| file.path.clone());
    let site = |path: &str, fresh: SnapshotFreshness| pointer(path, None, None, fresh);
    let hop =
        |path: &str, fresh: SnapshotFreshness, accuracy: Accuracy| -> Result<Vec<FileImpactHop>> {
            let Some(defining) = &defining else {
                return Ok(Vec::new());
            };
            Ok(vec![FileImpactHop {
                from: file_id(defining),
                to: file_id(path),
                site: site(path, fresh)?,
                start_byte: 0,
                end_byte: 0,
                accuracy,
            }])
        };
    let mut dropped = 0u64;
    let mut dependents = Vec::new();
    for caller in &found.callers.items {
        let accuracy = match caller.via {
            CallerVia::NameOnly if !query.include_name_only => continue,
            CallerVia::NameOnly => Accuracy::NameOnly,
            // File-level import edges, never a resolved import of the symbol.
            CallerVia::Imports | CallerVia::Dependent => Accuracy::ImportedFile,
        };
        let Some(fresh) = freshness(dirty, &caller.path) else {
            dropped += 1;
            continue;
        };
        let hops = hop(&caller.path, fresh, accuracy)?;
        dependents.push(dependent(site(&caller.path, fresh)?, hops));
    }
    let mut tests = Vec::new();
    for test in &found.tests.items {
        let Some(fresh) = freshness(dirty, &test.path) else {
            dropped += 1;
            continue;
        };
        // A defining file's own inline tests are zero hops from it.
        let hops = match test.how {
            Some(CoverHow::Inline) => Vec::new(),
            _ => hop(&test.path, fresh, Accuracy::ImportedFile)?,
        };
        tests.push(dependent(site(&test.path, fresh)?, hops));
    }
    // Every visibility is a candidate; only core's check makes a hit.
    let mut targets: Vec<(&str, Vec<u8>)> = found
        .files
        .iter()
        .map(|file| ("file", file.key.clone()))
        .collect();
    targets.extend(found.symbols.iter().map(|s| ("symbol", s.key.clone())));
    let linked = records::linked(shared, checker, &targets)?;
    let pending = !dirty.paths.is_empty() || dirty.overflowed;
    let floor = found.callers.more_is_floor
        || found.tests.more_is_floor
        || found.deadline_reached
        || linked.limited
        || pending;
    let mut value = Impact {
        dependents,
        tests,
        records: linked.hits,
        omitted_frontier: (found.callers.more + found.tests.more) as u64,
        frontier_count_complete: !floor,
        next: None,
        complete: false,
    };
    let mut index = index.clone();
    if found.deadline_reached {
        index.note(CoverageReason::TimeLimit);
    }
    if pending || dropped > 0 {
        index.note(CoverageReason::StaleSnapshot);
    }
    fit_impact(&index, &mut value, query.budget.max_bytes as usize);
    value.complete =
        value.omitted_frontier == 0 && value.frontier_count_complete && !found.definitions_capped;
    checked(answer(&index, Read::Present { value }), query.budget)
}

fn dependent(pointer: CodePointer, file_hops: Vec<FileImpactHop>) -> Dependent {
    Dependent {
        pointer,
        symbol: None,
        hops: Vec::new(),
        file_hops,
    }
}

/// Drop the last listed rows until the answer fits, counting each.
fn fit_impact(index: &IndexSummary, value: &mut Impact, max_bytes: usize) {
    while size(&answer(
        index,
        Read::Present {
            value: value.clone(),
        },
    )) > max_bytes
    {
        let dropped = if value.tests.len() > value.dependents.len() {
            value.tests.pop().is_some()
        } else {
            value.dependents.pop().is_some() || value.records.pop().is_some()
        };
        if !dropped {
            return;
        }
        value.omitted_frontier += 1;
    }
}
