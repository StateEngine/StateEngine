//! Related is a bounded graph expansion of broad hits, with authoritative records.
use super::{
    candidates::{Candidate, Candidates, Kind},
    *,
};
use rusqlite::types::Value;
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn collect(
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    query: &FindQuery,
    end: Instant,
) -> AtlasResult<Candidates> {
    let mut seeds_query = query.clone();
    seeds_query.kind = SearchKind::All;
    let seeds =
        super::candidates::collect(env, sql, snapshot, &seeds_query, SearchMode::Broad, end)?;
    let mut output = Candidates {
        values: Vec::new(),
        truncated: seeds.truncated,
    };
    let mut identities = Vec::new();
    for seed in seeds.values.iter().take(8) {
        if let Some((_, _, related)) = identities
            .iter_mut()
            .find(|(kind, id, _)| *kind == seed.kind && *id == seed.rowid)
        {
            *related = false;
        } else {
            identities.push((seed.kind, seed.rowid, false));
        }
        for (kind, id) in neighbors(sql, seed, &mut output.truncated, end)? {
            if !identities.iter().any(|(k, i, _)| *k == kind && *i == id) {
                if identities.len() == 256 {
                    output.truncated = true;
                    break;
                }
                identities.push((kind, id, true));
            }
        }
        if Instant::now() >= end {
            output.truncated = true;
            break;
        }
    }
    let mut resident = 0;
    for (kind, rowid, related) in identities {
        if Instant::now() >= end {
            output.truncated = true;
            break;
        }
        if !allowed(sql, kind, rowid, query)? {
            continue;
        }
        if related && matches!(kind, Kind::Symbol | Kind::File) {
            let file = if kind == Kind::Symbol {
                symbol_by_id(sql, rowid)?.1
            } else {
                rowid
            };
            if !matches!(file_by_id(sql, file)?.coverage, FileCoverage::Indexed) {
                output.truncated = true;
                continue;
            }
        }
        let (key, tie) = super::candidates::metadata(sql, kind, rowid)?;
        if kind == Kind::Record {
            let pointer = super::candidates::record_pointer(sql, rowid)?;
            match env
                .records
                .read(&snapshot.index.project, env.viewer, &pointer, None)?
            {
                Read::Present { value } if value.pointer == pointer => (),
                Read::Absent { .. } => continue,
                _ => return Err(cache_error("related record authority unavailable")),
            }
        }
        let tag = match kind {
            Kind::Symbol => "symbol",
            Kind::File => "file",
            Kind::Record => "record",
            Kind::Commit => "commit",
        };
        let mut activity = crate::rank::activity(
            sql,
            tag,
            &key,
            crate::rank::ActivityQuery {
                project: &snapshot.index.project,
                viewer: env.viewer,
                records: env.records,
                now: env.now_unix_ms,
            },
        )?;
        let path = if kind == Kind::Symbol {
            Some(file_by_id(sql, symbol_by_id(sql, rowid)?.1)?.pointer.path)
        } else {
            None
        };
        if crate::rank::downweight(
            path.as_ref().map_or(tie.as_str(), |p| p.as_str()),
            query.kind,
        ) {
            activity.score *= 0.5;
        }
        let lexical = seeds
            .values
            .iter()
            .find(|c| c.kind == kind && c.rowid == rowid)
            .map_or(0.0, |c| c.lexical);
        resident += key.len() + tie.len() + 160;
        output.values.push(Candidate {
            kind,
            rowid,
            tier: 4,
            key,
            tie,
            activity,
            precomputed_last: None,
            lexical,
            related,
        });
        output
            .values
            .sort_by_cached_key(|c| super::find::key(c, query.order));
        while output.values.len() > 128 || resident > 24576 {
            let old = output
                .values
                .pop()
                .ok_or_else(|| cache_error("related admission underflow"))?;
            resident -= old.key.len() + old.tie.len() + 160;
            output.truncated = true;
        }
    }
    Ok(output)
}
fn ids(
    sql: &SqlView<'_>,
    statement: &str,
    value: Value,
    limited: &mut bool,
) -> AtlasResult<Vec<i64>> {
    let mut statement = sql.prepare(statement)?;
    let mut rows = statement.query([value]).map_err(cache_error)?;
    let mut output = Vec::new();
    while let Some(row) = rows.next().map_err(cache_error)? {
        output.push(get(row, 0)?);
    }
    if output.len() > 32 {
        output.truncate(32);
        *limited = true;
    }
    Ok(output)
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn neighbors(
    sql: &SqlView<'_>,
    seed: &Candidate,
    limited: &mut bool,
    end: Instant,
) -> AtlasResult<Vec<(Kind, i64)>> {
    let mut output = Vec::new();
    let mut files = Vec::new();
    if matches!(seed.kind, Kind::Symbol | Kind::File) {
        let file = if seed.kind == Kind::Symbol {
            symbol_by_id(sql, seed.rowid)?.1
        } else {
            seed.rowid
        };
        if !matches!(file_by_id(sql, file)?.coverage, FileCoverage::Indexed) {
            *limited = true;
            return Ok(output);
        }
    }
    if seed.kind == Kind::Symbol {
        for statement in [
            "SELECT target FROM refs WHERE enclosing=?1 AND target IS NOT NULL AND accuracy<>'NameOnly' ORDER BY target LIMIT 33",
            "SELECT enclosing FROM refs WHERE target=?1 AND enclosing IS NOT NULL AND accuracy<>'NameOnly' ORDER BY enclosing LIMIT 33",
        ] {
            output.extend(
                ids(sql, statement, Value::Integer(seed.rowid), limited)?
                    .into_iter()
                    .map(|id| (Kind::Symbol, id)),
            );
        }
        files.push(symbol_by_id(sql, seed.rowid)?.1);
    } else if seed.kind == Kind::File {
        files.push(seed.rowid);
    }
    let tag = match seed.kind {
        Kind::Symbol => "symbol",
        Kind::File => "file",
        Kind::Record => "record",
        Kind::Commit => "commit",
    };
    for id in ids(
        sql,
        &format!(
            "SELECT source_id FROM mentions WHERE target_kind='{tag}' AND target_key=?1 AND source_kind='record' ORDER BY source_id LIMIT 33"
        ),
        Value::Blob(seed.key.clone()),
        limited,
    )? {
        output.push((Kind::Record, id));
    }
    if matches!(seed.kind, Kind::Record | Kind::Commit) {
        for (kind, table, key) in [
            (Kind::File, "files", "key"),
            (Kind::Symbol, "symbols", "key"),
            (Kind::Record, "records", "record_id"),
        ] {
            let target = match kind {
                Kind::File => "file",
                Kind::Symbol => "symbol",
                _ => "record",
            };
            let target_key = if kind == Kind::Record {
                "CAST(target_key AS TEXT)"
            } else {
                "target_key"
            };
            let statement = format!(
                "SELECT id FROM {table} WHERE {key} IN (SELECT {target_key} FROM mentions WHERE source_kind='{tag}' AND source_id=?1 AND target_kind='{target}') ORDER BY id LIMIT 33"
            );
            for id in ids(sql, &statement, Value::Integer(seed.rowid), limited)? {
                output.push((kind, id));
                if kind == Kind::File {
                    files.push(id);
                }
            }
        }
    }
    for file in files {
        let row = file_by_id(sql, file)?;
        if crate::policy::built_in_denied(&row.pointer.path)
            || !matches!(row.coverage, FileCoverage::Indexed)
        {
            *limited = true;
            continue;
        }
        if output.len() >= 256 || Instant::now() >= end {
            *limited = true;
            break;
        }
        for (kind, statement) in [
            (
                Kind::Symbol,
                "SELECT id FROM symbols WHERE file=?1 ORDER BY start_byte,id LIMIT 33",
            ),
            (
                Kind::File,
                "SELECT file FROM imports WHERE target_file=?1 ORDER BY file LIMIT 33",
            ),
            (
                Kind::File,
                "SELECT target_file FROM imports WHERE file=?1 AND target_file IS NOT NULL ORDER BY target_file LIMIT 33",
            ),
        ] {
            output.extend(
                ids(sql, statement, Value::Integer(file), limited)?
                    .into_iter()
                    .map(|id| (kind, id)),
            );
        }
        let key = file_by_id(sql, file)?.pointer.file;
        output.extend(ids(sql, "SELECT source_id FROM mentions WHERE target_kind='file' AND target_key=?1 AND source_kind='record' ORDER BY source_id LIMIT 33", Value::Blob(key.0.to_vec()), limited)?.into_iter().map(|id|(Kind::Record,id)));
    }
    Ok(output)
}
fn allowed(sql: &SqlView<'_>, kind: Kind, id: i64, query: &FindQuery) -> AtlasResult<bool> {
    let kind_allowed = match kind {
        Kind::Symbol => matches!(
            query.kind,
            SearchKind::All | SearchKind::Code | SearchKind::Symbol
        ),
        Kind::File => matches!(
            query.kind,
            SearchKind::All | SearchKind::Code | SearchKind::Path
        ),
        Kind::Commit => matches!(query.kind, SearchKind::All | SearchKind::Commit),
        Kind::Record => {
            let pointer = super::candidates::record_pointer(sql, id)?;
            matches!(
                (query.kind, pointer.kind),
                (SearchKind::All, _)
                    | (SearchKind::Message, RecordKind::Message)
                    | (SearchKind::Working, RecordKind::Working)
                    | (SearchKind::Edit, RecordKind::Edit)
            )
        }
    };
    if !kind_allowed {
        return Ok(false);
    }
    if matches!(kind, Kind::File | Kind::Symbol) {
        let file = if kind == Kind::Symbol {
            symbol_by_id(sql, id)?.1
        } else {
            id
        };
        if crate::policy::built_in_denied(&file_by_id(sql, file)?.pointer.path) {
            return Ok(false);
        }
    }
    if query.scope.paths.is_empty() && query.scope.languages.is_empty() {
        return Ok(true);
    }
    let file = match kind {
        Kind::File => id,
        Kind::Symbol => symbol_by_id(sql, id)?.1,
        _ => return Ok(false),
    };
    let file = file_by_id(sql, file)?;
    Ok(query.scope.includes_path(&file.pointer.path)
        && (query.scope.languages.is_empty()
            || file
                .language
                .is_some_and(|l| query.scope.languages.contains(&l))))
}
