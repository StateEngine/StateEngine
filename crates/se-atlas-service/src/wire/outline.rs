//! `outline` on the wire. A file the watcher reported changed or removed is
//! read through custody as it is now: an editor's atomic save reports the
//! old name removed while the new file already sits there, so only custody
//! decides whether the file is gone, private or present.
use super::{
    answer, checked, kind, language,
    nav::{refused, unresolved},
    pointer, records, size, span, unknown,
};
use crate::{
    error::{index_error, sqlite},
    read::{RecordCheck, STARTING},
    root::{Dirty, Shared},
};
use rusqlite::{Connection, OptionalExtension};
use se_atlas_index::{
    custody::GuardedRead,
    extract::{self, file_key, flags},
};
use se_atlas_query::{
    Answer as Found, Target,
    outline::{Incomplete, OutlineRequest},
};
use se_types::code::AtlasText as _;
use se_types::{
    Read, Result,
    code::{
        Answer, AtlasTarget, CoverageReason, FileCoverage, IndexSummary, Outline, OutlineQuery,
        OutlineSymbol, SnapshotFreshness, SymbolId,
    },
};
use std::collections::HashMap;

pub(crate) fn outline(
    shared: &Shared,
    index: &IndexSummary,
    dirty: &Dirty,
    query: &OutlineQuery,
    records: &dyn RecordCheck,
) -> Result<Answer<Read<Outline>>> {
    let path = query.path.as_str();
    let limit = usize::from(query.budget.max_results);
    let mut value = if dirty.change(path).is_some() {
        match live(shared, path, limit)? {
            Live::Outline(value) => *value,
            Live::Absent => {
                return Ok(unknown(
                    index,
                    &format!("{path} was deleted; the index is catching up"),
                ));
            }
            Live::Refused => return Ok(unknown(index, &refused(path))),
            Live::Starting => return Ok(unknown(index, STARTING)),
        }
    } else {
        let request = OutlineRequest {
            target: Target::File(path.to_owned()),
            limit,
        };
        let found = shared.with_reader(|reader| {
            let found =
                se_atlas_query::outline::outline(reader, &request).map_err(|e| index_error(&e))?;
            match found {
                Found::Found(outline) => indexed(reader.connection(), &outline).map(Found::Found),
                Found::Refused { path } => Ok(Found::Refused { path }),
                Found::NotFound { suggestions } => Ok(Found::NotFound { suggestions }),
            }
        })?;
        match unresolved(index, found, &AtlasTarget::File(query.path.clone()))? {
            Ok(value) => value,
            Err(answer) => return Ok(answer),
        }
    };
    let linked = records::linked(shared, records, &[("file", file_key(path).to_vec())])?;
    value.records = linked.hits;
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

fn indexed(conn: &Connection, outline: &se_atlas_query::outline::Outline) -> Result<Outline> {
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
        Some(Incomplete::Binary) => binary(),
        Some(Incomplete::Minified) => partial(CoverageReason::SourceBytesLimit),
        Some(Incomplete::Truncated) => partial(CoverageReason::ResultLimit),
        Some(Incomplete::ExtractFailed) => partial(CoverageReason::ParseErrors),
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

fn binary() -> FileCoverage {
    FileCoverage::Deferred {
        reason: CoverageReason::UnsupportedEncoding,
    }
}

fn partial(reason: CoverageReason) -> FileCoverage {
    FileCoverage::Partial {
        reasons: vec![reason],
    }
}

/// What custody found at a changed file's name.
enum Live {
    Outline(Box<Outline>),
    Absent,
    Refused,
    Starting,
}

/// Outline a changed file from its current bytes, read through custody,
/// keeping every reason the extraction was incomplete.
fn live(shared: &Shared, path: &str, limit: usize) -> Result<Live> {
    let Some(source) = shared.source() else {
        return Ok(Live::Starting);
    };
    let file = match source
        .read_guarded_file(path)
        .map_err(|e| index_error(&e.into()))?
    {
        GuardedRead::Source(file) => file,
        GuardedRead::Absent => return Ok(Live::Absent),
        GuardedRead::Denied | GuardedRead::Refused => return Ok(Live::Refused),
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
    let set = |flag: u32| extracted.flags & flag != 0;
    let mut reasons = Vec::new();
    if file.prefix_only || set(flags::MINIFIED) {
        reasons.push(CoverageReason::SourceBytesLimit);
    }
    if set(flags::TRUNCATED) {
        reasons.push(CoverageReason::ResultLimit);
    }
    if set(flags::EXTRACT_FAILED) {
        reasons.push(CoverageReason::ParseErrors);
    }
    let coverage = if set(flags::BINARY) {
        binary()
    } else if reasons.is_empty() {
        FileCoverage::Indexed
    } else {
        FileCoverage::Partial { reasons }
    };
    Ok(Live::Outline(Box::new(Outline {
        file: pointer(path, None, Some(extracted.hash), SnapshotFreshness::Current)?,
        language: language(extracted.lang.as_str(), path),
        complete: matches!(coverage, FileCoverage::Indexed) && extracted.symbols.len() <= limit,
        coverage,
        symbols,
        records: Vec::new(),
        next: None,
    })))
}
