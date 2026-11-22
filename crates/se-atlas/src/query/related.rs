//! Related is a bounded graph expansion of broad hits, with authoritative records.
use super::{
    candidates::{Candidate, Candidates, Kind},
    *,
};
use rusqlite::types::Value;
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
    let identities = expand(sql, &seeds, &mut output.truncated, end)?;
    let mut resident = 0;
    for identity in identities {
        super::candidates::admission_time(end)?;
        let truncated = &mut output.truncated;
        let Some(candidate) = admit(env, sql, snapshot, query, &seeds, identity, truncated)? else {
            continue;
        };
        resident += candidate.key.len() + candidate.tie.len() + 160;
        output.values.push(candidate);
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
/// Seeds keep their own identity; their neighbors are marked related, up to 256 identities.
fn expand(
    sql: &SqlView<'_>,
    seeds: &Candidates,
    truncated: &mut bool,
    end: Instant,
) -> AtlasResult<Vec<(Kind, i64, bool)>> {
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
        for (kind, id) in neighbors(sql, seed, truncated, end)? {
            if !identities.iter().any(|(k, i, _)| *k == kind && *i == id) {
                if identities.len() == 256 {
                    *truncated = true;
                    break;
                }
                identities.push((kind, id, true));
            }
        }
        super::candidates::admission_time(end)?;
    }
    Ok(identities)
}
fn admit(
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    query: &FindQuery,
    seeds: &Candidates,
    (kind, rowid, related): (Kind, i64, bool),
    truncated: &mut bool,
) -> AtlasResult<Option<Candidate>> {
    if !allowed(sql, kind, rowid, query)? {
        return Ok(None);
    }
    let file = owning_file(sql, kind, rowid)?;
    if related
        && let Some(file) = file
        && !matches!(file_by_id(sql, file)?.coverage, FileCoverage::Indexed)
    {
        *truncated = true;
        return Ok(None);
    }
    let (key, tie) = super::candidates::metadata(sql, kind, rowid)?;
    if kind == Kind::Record {
        let pointer = super::candidates::record_pointer(sql, rowid)?;
        match env
            .records
            .read(&snapshot.index.project, env.viewer, &pointer, None)?
        {
            Read::Present { value } if value.pointer == pointer => (),
            Read::Absent { .. } => return Ok(None),
            _ => return Err(cache_error("related record authority unavailable")),
        }
    }
    let mut activity = crate::rank::activity(
        sql,
        kind.tag(),
        &key,
        crate::rank::ActivityQuery {
            project: &snapshot.index.project,
            viewer: env.viewer,
            records: env.records,
            now: env.now_unix_ms,
        },
    )?;
    let path = match (kind, file) {
        (Kind::Symbol, Some(file)) => Some(file_by_id(sql, file)?.pointer.path),
        _ => None,
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
    Ok(Some(Candidate {
        kind,
        rowid,
        tier: 4,
        key,
        tie,
        activity,
        precomputed_last: None,
        lexical,
        related,
        downweighted: false,
    }))
}
/// The file that owns a symbol or file identity; records and commits own none.
fn owning_file(sql: &SqlView<'_>, kind: Kind, id: i64) -> AtlasResult<Option<i64>> {
    Ok(match kind {
        Kind::Symbol => Some(symbol_by_id(sql, id)?.1),
        Kind::File => Some(id),
        Kind::Record | Kind::Commit => None,
    })
}
fn ids(
    sql: &SqlView<'_>,
    statement: &str,
    value: Value,
    kind: Kind,
    limited: &mut bool,
) -> AtlasResult<Vec<(Kind, i64)>> {
    let mut output = all(sql, statement, [value], 0, |row| Ok((kind, get(row, 0)?)))?;
    if output.len() > 32 {
        output.truncate(32);
        *limited = true;
    }
    Ok(output)
}
fn neighbors(
    sql: &SqlView<'_>,
    seed: &Candidate,
    limited: &mut bool,
    end: Instant,
) -> AtlasResult<Vec<(Kind, i64)>> {
    let mut output = Vec::new();
    let mut files = Vec::new();
    if let Some(file) = owning_file(sql, seed.kind, seed.rowid)? {
        if !matches!(file_by_id(sql, file)?.coverage, FileCoverage::Indexed) {
            *limited = true;
            return Ok(output);
        }
        files.push(file);
    }
    if seed.kind == Kind::Symbol {
        for statement in [
            "SELECT target FROM refs WHERE enclosing=?1 AND target IS NOT NULL AND accuracy<>'NameOnly' ORDER BY target LIMIT 33",
            "SELECT enclosing FROM refs WHERE target=?1 AND enclosing IS NOT NULL AND accuracy<>'NameOnly' ORDER BY enclosing LIMIT 33",
        ] {
            let value = Value::Integer(seed.rowid);
            output.extend(ids(sql, statement, value, Kind::Symbol, limited)?);
        }
    }
    let tag = seed.kind.tag();
    output.extend(ids(
        sql,
        &format!(
            "SELECT source_id FROM mentions WHERE target_kind='{tag}' AND target_key=?1 AND source_kind='record' ORDER BY source_id LIMIT 33"
        ),
        Value::Blob(seed.key.clone()),
        Kind::Record,
        limited,
    )?);
    if matches!(seed.kind, Kind::Record | Kind::Commit) {
        for (kind, table, key, target_key) in [
            (Kind::File, "files", "key", "target_key"),
            (Kind::Symbol, "symbols", "key", "target_key"),
            (
                Kind::Record,
                "records",
                "record_id",
                "CAST(target_key AS TEXT)",
            ),
        ] {
            let target = kind.tag();
            let statement = format!(
                "SELECT id FROM {table} WHERE {key} IN (SELECT {target_key} FROM mentions WHERE source_kind='{tag}' AND source_id=?1 AND target_kind='{target}') ORDER BY id LIMIT 33"
            );
            for (kind, id) in ids(sql, &statement, Value::Integer(seed.rowid), kind, limited)? {
                output.push((kind, id));
                if kind == Kind::File {
                    files.push(id);
                }
            }
        }
    }
    file_neighbors(sql, files, &mut output, limited, end)?;
    Ok(output)
}
fn file_neighbors(
    sql: &SqlView<'_>,
    files: Vec<i64>,
    output: &mut Vec<(Kind, i64)>,
    limited: &mut bool,
    end: Instant,
) -> AtlasResult<()> {
    for file in files {
        let row = file_by_id(sql, file)?;
        if crate::policy::built_in_denied(&row.pointer.path)
            || !matches!(row.coverage, FileCoverage::Indexed)
        {
            *limited = true;
            continue;
        }
        super::candidates::admission_time(end)?;
        if output.len() >= 256 {
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
            output.extend(ids(sql, statement, Value::Integer(file), kind, limited)?);
        }
        let key = Value::Blob(row.pointer.file.0.to_vec());
        output.extend(ids(sql, "SELECT source_id FROM mentions WHERE target_kind='file' AND target_key=?1 AND source_kind='record' ORDER BY source_id LIMIT 33", key, Kind::Record, limited)?);
    }
    Ok(())
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
    if let Some(file) = owning_file(sql, kind, id)?
        && crate::policy::built_in_denied(&file_by_id(sql, file)?.pointer.path)
    {
        return Ok(false);
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
