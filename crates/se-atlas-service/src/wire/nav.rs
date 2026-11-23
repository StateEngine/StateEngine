//! `refs`, `impact` and `outline` on the wire. A private path and an
//! unindexed name are different answers; an outline of a file the watcher
//! reported changed is extracted from the file as it is now.
use super::{
    PageFacts, answer, checked, cursor, file_id, kind, language, page, pointer, size, span, unknown,
};
use crate::{
    dirty::Change,
    error::{index_error, sqlite},
    read::{RecordCheck, STARTING},
    root::Shared,
};
use rusqlite::{Connection, OptionalExtension};
use se_atlas_index::{custody::GuardedRead, extract, store::Reader};
use se_atlas_query::{
    Answer as Found, Target,
    impact::{CallerVia, ImpactRequest},
    outline::{Incomplete, OutlineRequest},
    refs::{RefAccuracy, RefsRequest},
};
use se_types::code::AtlasText as _;
use se_types::{
    Page, Read, Result, SeError,
    code::{
        Accuracy, Answer, AtlasTarget, CoverageReason, Dependent, FileCoverage, FileImpactHop,
        Impact, ImpactQuery, IndexSummary, Outline, OutlineQuery, OutlineSymbol, RecordHit,
        RecordKey, RecordKind, RecordPointer, Reference, ReferenceHit, ReferenceKind, RefsQuery,
        SnapshotFreshness, SymbolId, SymbolSelector,
    },
};
use std::collections::HashMap;

/// Serialized bytes assumed per listed reference or dependent when sizing a
/// page; the page is still measured exactly before it is returned.
const ROW_BYTES: usize = 360;

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
fn unresolved<T, U>(
    index: &IndexSummary,
    found: Found<U>,
    asked: &AtlasTarget,
) -> Result<std::result::Result<U, Answer<Read<T>>>> {
    match found {
        Found::Found(value) => Ok(Ok(value)),
        Found::Refused { path } => Ok(Err(unknown(
            index,
            &format!(
                "{path} is a private file Atlas never reads or indexes; open it directly if you need it"
            ),
        ))),
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

fn with_reader<T>(shared: &Shared, read: impl FnOnce(&Reader) -> Result<T>) -> Result<T> {
    let reader = shared.reader()?;
    let result = read(&reader);
    shared.give_back(reader);
    result
}

pub(crate) fn refs(
    shared: &Shared,
    index: &IndexSummary,
    query: &RefsQuery,
) -> Result<Answer<Read<Page<ReferenceHit>>>> {
    let Some(source) = shared.source() else {
        return Ok(unknown(index, STARTING));
    };
    let fit = (query.budget.max_bytes as usize / ROW_BYTES).max(1);
    let request = RefsRequest {
        target: target(&query.target)?,
        limit: usize::from(query.budget.max_results).min(fit),
        cursor: match &query.next {
            Some(next) => Some(usize::try_from(cursor::number('r', next)?).unwrap_or(usize::MAX)),
            None => None,
        },
        deadline: query.budget.work,
    };
    let found = with_reader(shared, |reader| {
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
    let mut items = Vec::new();
    for group in &refs.groups {
        let accuracy = match group.accuracy {
            RefAccuracy::ImportedFile => Accuracy::ExplicitImport,
            RefAccuracy::NameOnly if query.include_name_only => Accuracy::NameOnly,
            RefAccuracy::NameOnly => continue,
        };
        for line in &group.lines {
            let text = line.text.trim_start();
            let import = ["use ", "import ", "from ", "#include", "require("]
                .iter()
                .any(|lead| text.starts_with(lead));
            items.push(ReferenceHit::Code(Reference {
                site: pointer(
                    &group.path,
                    Some((line.line, line.line)),
                    None,
                    SnapshotFreshness::Current,
                )?,
                kind: if import {
                    ReferenceKind::Import
                } else {
                    ReferenceKind::ValueUse
                },
                spelling: line.text.clone(),
                enclosing: None,
                resolved_target: resolved,
                accuracy,
            }));
        }
    }
    let partial = refs.deadline_reached || refs.files_read_failed > 0 || refs.files_partly_read > 0;
    let mut index = index.clone();
    if refs.deadline_reached {
        index.note(CoverageReason::TimeLimit);
    }
    let next = refs
        .next_cursor
        .map(|at| cursor::wrap('r', &at.to_string()))
        .transpose()?;
    let bytes = items.iter().map(|item| size(item) + 1).sum();
    let value = page(
        items,
        PageFacts {
            index: &index,
            budget: query.budget,
            after: query.next.as_ref(),
            next,
            partial,
            bytes,
        },
    )?;
    checked(answer(&index, Read::Present { value }), query.budget)
}

pub(crate) fn impact(
    shared: &Shared,
    index: &IndexSummary,
    query: &ImpactQuery,
    records: &dyn RecordCheck,
) -> Result<Answer<Read<Impact>>> {
    let request = ImpactRequest {
        target: target(&query.target)?,
        depth: u32::from(query.depth),
        deadline: query.budget.work,
    };
    let (found, linked) = with_reader(shared, |reader| {
        let found =
            se_atlas_query::impact::impact(reader, &request).map_err(|e| index_error(&e))?;
        let linked = match &found {
            Found::Found(impact) => impact
                .records
                .items
                .iter()
                .map(|record| record_pointer(reader.connection(), &record.record_id))
                .collect::<Result<Vec<_>>>()?,
            _ => Vec::new(),
        };
        Ok((found, linked))
    })?;
    let found = match unresolved(index, found, &query.target)? {
        Ok(found) => found,
        Err(answer) => return Ok(answer),
    };
    let defining = found.files.first().map(|file| file.path.clone());
    let hop = |path: &str, accuracy: Accuracy| -> Result<Vec<FileImpactHop>> {
        let Some(defining) = &defining else {
            return Ok(Vec::new());
        };
        Ok(vec![FileImpactHop {
            from: file_id(defining),
            to: file_id(path),
            site: pointer(path, None, None, SnapshotFreshness::Current)?,
            start_byte: 0,
            end_byte: 0,
            accuracy,
        }])
    };
    let mut dependents = Vec::new();
    for caller in &found.callers.items {
        let accuracy = match caller.via {
            CallerVia::NameOnly if !query.include_name_only => continue,
            CallerVia::NameOnly => Accuracy::NameOnly,
            CallerVia::Imports | CallerVia::Dependent => Accuracy::ExplicitImport,
        };
        dependents.push(dependent(&caller.path, hop(&caller.path, accuracy)?)?);
    }
    let mut tests = Vec::new();
    for test in &found.tests.items {
        tests.push(dependent(
            &test.path,
            hop(&test.path, Accuracy::ExplicitImport)?,
        )?);
    }
    let mut hits: Vec<RecordHit> = Vec::new();
    for pointer in linked.into_iter().flatten() {
        if let Read::Present { value } = records.hit(&pointer, None)? {
            hits.push(value);
        }
    }
    let floor = found.callers.more_is_floor || found.tests.more_is_floor || found.deadline_reached;
    let mut value = Impact {
        dependents,
        tests,
        records: hits,
        omitted_frontier: (found.callers.more + found.tests.more) as u64,
        frontier_count_complete: !floor,
        next: None,
        complete: false,
    };
    let mut index = index.clone();
    if found.deadline_reached {
        index.note(CoverageReason::TimeLimit);
    }
    fit_impact(&index, &mut value, query.budget.max_bytes as usize);
    value.complete =
        value.omitted_frontier == 0 && value.frontier_count_complete && !found.definitions_capped;
    checked(answer(&index, Read::Present { value }), query.budget)
}

fn dependent(path: &str, file_hops: Vec<FileImpactHop>) -> Result<Dependent> {
    Ok(Dependent {
        pointer: pointer(path, None, None, SnapshotFreshness::Current)?,
        symbol: None,
        hops: Vec::new(),
        file_hops,
    })
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

/// A record's pointer, from the store's copy of its identity.
fn record_pointer(conn: &Connection, record_id: &str) -> Result<Option<RecordPointer>> {
    let row: Option<(String, String)> = conn
        .prepare_cached("SELECT kind, source_event FROM records WHERE record_id=?1")
        .and_then(|mut select| {
            select
                .query_row([record_id], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()
        })
        .map_err(|e| sqlite(&e))?;
    let Some((kind, event)) = row else {
        return Ok(None);
    };
    let kind = match kind.as_str() {
        "decision" => RecordKind::Decision,
        "message" => RecordKind::Message,
        "working" => RecordKind::Working,
        "edit" => RecordKind::Edit,
        "commit" => RecordKind::Commit,
        _ => return Ok(None),
    };
    let (Ok(key), Ok(source_event)) = (RecordKey::new(record_id), event.parse()) else {
        return Ok(None);
    };
    Ok(Some(RecordPointer {
        key,
        kind,
        source_event,
    }))
}

pub(crate) fn outline(
    shared: &Shared,
    index: &IndexSummary,
    query: &OutlineQuery,
    records: &dyn RecordCheck,
) -> Result<Answer<Read<Outline>>> {
    let path = query.path.as_str();
    let dirty = shared.dirty()?.change(path);
    let limit = usize::from(query.budget.max_results);
    let mut value = match dirty {
        Some(Change::Removed) => {
            return Ok(unknown(
                index,
                &format!("{path} was deleted; the index is catching up"),
            ));
        }
        Some(Change::Modified) => match live_outline(shared, path, limit)? {
            Some(value) => value,
            None => return Ok(unknown(index, STARTING)),
        },
        None => {
            let request = OutlineRequest {
                target: Target::File(path.to_owned()),
                limit,
            };
            let found = with_reader(shared, |reader| {
                let found = se_atlas_query::outline::outline(reader, &request)
                    .map_err(|e| index_error(&e))?;
                match found {
                    Found::Found(outline) => {
                        indexed_outline(reader.connection(), &outline).map(Found::Found)
                    }
                    Found::Refused { path } => Ok(Found::Refused { path }),
                    Found::NotFound { suggestions } => Ok(Found::NotFound { suggestions }),
                }
            })?;
            match unresolved(index, found, &AtlasTarget::File(query.path.clone()))? {
                Ok(value) => value,
                Err(answer) => return Ok(answer),
            }
        }
    };
    value.records = outline_records(shared, path, records)?;
    while size(&answer(
        index,
        Read::Present {
            value: value.clone(),
        },
    )) > query.budget.max_bytes as usize
        && value.symbols.pop().is_some()
    {
        value.complete = false;
    }
    checked(answer(index, Read::Present { value }), query.budget)
}

fn indexed_outline(
    conn: &Connection,
    outline: &se_atlas_query::outline::Outline,
) -> Result<Outline> {
    let mut keys: HashMap<i64, [u8; 32]> = HashMap::new();
    {
        let mut select = conn
            .prepare_cached("SELECT id, key FROM sym WHERE file=?1")
            .map_err(|e| sqlite(&e))?;
        let rows = select
            .query_map([outline.file.id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| sqlite(&e))?;
        for row in rows {
            let (id, key) = row.map_err(|e| sqlite(&e))?;
            if let Some(key) = super::hash(Some(key)) {
                keys.insert(id, key);
            }
        }
    }
    let hash: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hash FROM files WHERE id=?1",
            [outline.file.id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| sqlite(&e))?;
    let symbols = outline
        .entries
        .iter()
        .filter_map(|entry| {
            Some(OutlineSymbol {
                id: SymbolId(*keys.get(&entry.id)?),
                parent: entry
                    .parent
                    .and_then(|parent| keys.get(&parent))
                    .map(|key| SymbolId(*key)),
                name: entry.name.clone(),
                kind: kind(entry.kind?),
                span: span(entry.line, entry.end_line),
            })
        })
        .collect();
    let coverage = match outline.incomplete {
        None => FileCoverage::Indexed,
        Some(Incomplete::Binary) => FileCoverage::Deferred {
            reason: CoverageReason::UnsupportedEncoding,
        },
        Some(Incomplete::Minified) => FileCoverage::Partial {
            reasons: vec![CoverageReason::SourceBytesLimit],
        },
        Some(Incomplete::Truncated) => FileCoverage::Partial {
            reasons: vec![CoverageReason::ResultLimit],
        },
        Some(Incomplete::ExtractFailed) => FileCoverage::Partial {
            reasons: vec![CoverageReason::ParseErrors],
        },
    };
    Ok(Outline {
        file: pointer(
            &outline.file.path,
            None,
            super::hash(hash),
            SnapshotFreshness::Current,
        )?,
        language: language(&outline.file.lang, &outline.file.path),
        complete: outline.omitted == 0 && outline.incomplete.is_none(),
        coverage,
        symbols,
        records: Vec::new(),
        next: None,
    })
}

/// Outline a changed file from its current bytes, read through custody.
fn live_outline(shared: &Shared, path: &str, limit: usize) -> Result<Option<Outline>> {
    let Some(source) = shared.source() else {
        return Ok(None);
    };
    let file = match source
        .read_guarded_file(path)
        .map_err(|e| index_error(&e.into()))?
    {
        GuardedRead::Source(file) => file,
        GuardedRead::Absent | GuardedRead::Denied | GuardedRead::Refused => return Ok(None),
    };
    let extracted = extract::extract(path, &file.bytes, file.prefix_only);
    let symbols: Vec<OutlineSymbol> = extracted
        .symbols
        .iter()
        .take(limit)
        .map(|symbol| OutlineSymbol {
            id: SymbolId(symbol.key),
            parent: symbol
                .parent
                .and_then(|at| extracted.symbols.get(at))
                .map(|parent| SymbolId(parent.key)),
            name: symbol.name.clone(),
            kind: kind(symbol.kind),
            span: span(symbol.line, symbol.end_line),
        })
        .collect();
    Ok(Some(Outline {
        file: pointer(path, None, Some(extracted.hash), SnapshotFreshness::Current)?,
        language: language(extracted.lang.as_str(), path),
        coverage: if file.prefix_only {
            FileCoverage::Partial {
                reasons: vec![CoverageReason::SourceBytesLimit],
            }
        } else {
            FileCoverage::Indexed
        },
        complete: !file.prefix_only && extracted.symbols.len() <= limit,
        symbols,
        records: Vec::new(),
        next: None,
    }))
}

/// Records that mention the file, newest first; core checks each one.
fn outline_records(
    shared: &Shared,
    path: &str,
    records: &dyn RecordCheck,
) -> Result<Vec<RecordHit>> {
    let pointers = with_reader(shared, |reader| {
        let conn = reader.connection();
        let mut select = conn
            .prepare_cached(
                "SELECT r.record_id FROM mentions m JOIN records r ON r.id = m.source_id
                 JOIN files f ON f.key = m.target_key
                 WHERE m.source_kind='record' AND m.target_kind='file' AND f.path=?1
                 ORDER BY r.occurred_unix_ms DESC LIMIT 5",
            )
            .map_err(|e| sqlite(&e))?;
        let ids: Vec<String> = select
            .query_map([path], |row| row.get(0))
            .map_err(|e| sqlite(&e))?
            .collect::<rusqlite::Result<_>>()
            .map_err(|e| sqlite(&e))?;
        ids.iter()
            .map(|id| record_pointer(conn, id))
            .collect::<Result<Vec<_>>>()
    })?;
    let mut hits = Vec::new();
    for pointer in pointers.into_iter().flatten() {
        if let Read::Present { value } = records.hit(&pointer, None)? {
            hits.push(value);
        }
    }
    Ok(hits)
}
