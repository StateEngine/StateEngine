//! All functions run inside one CacheConnection::write transaction. Verification
//! of the original source snapshot is required immediately before that commit.
use super::*;
use crate::{
    cache::{connection::SqlView, write},
    errors::{AtlasResult, cache_error},
    lifecycle::*,
    model::*,
    resolve::imports::candidates,
    scope::Scope,
};
use rusqlite::{OptionalExtension, params};
use se_types::code::AtlasText;
type Previous = (i64, Option<Vec<u8>>, Option<u64>, String);
#[derive(Debug)]
pub struct Applied {
    pub generation: Generation,
    pub baseline_reset: bool,
    pub stale: bool,
}
/// Installs a complete parse or preserves exactly one last-good semantic set.
/// Failed/partial/deferred work never replaces that set with a smaller graph.
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn apply(
    sql: &SqlView<'_>,
    scope: &Scope,
    snapshot: &SourceSnapshot,
    parsed: &ParsedFile,
    cold: bool,
    serial: u64,
) -> AtlasResult<Applied> {
    if parsed.file != scope.file_id(&snapshot.path) || parsed.content_hash != snapshot.content_hash
    {
        return Err(cache_error("parse and source snapshot differ"));
    }
    let previous: Option<Previous> = sql
        .prepare(
            "SELECT id,indexed_hash,last_good_generation,coverage_json FROM files WHERE key=?1",
        )?
        .query_row([parsed.file.0.as_slice()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get::<_, Option<i64>>(2)?
                    .map(|v| {
                        u64::try_from(v).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                2,
                                rusqlite::types::Type::Integer,
                                Box::new(e),
                            )
                        })
                    })
                    .transpose()?,
                r.get(3)?,
            ))
        })
        .optional()
        .map_err(cache_error)?;
    let generation: u64 = unsigned(
        sql,
        "SELECT index_generation+1 FROM meta WHERE singleton=1",
        [],
    )?;
    let good = matches!(parsed.coverage, FileCoverage::Indexed);
    let baseline = previous.as_ref().and_then(|p| p.2);
    let prior_good = previous.as_ref().is_some_and(|p| p.3 == "\"Indexed\"");
    let reset = good && previous.is_some() && !prior_good;
    let old_hash = previous
        .as_ref()
        .and_then(|p| p.1.as_ref())
        .map(|v| {
            v.as_slice()
                .try_into()
                .map(ContentHash)
                .map_err(|_| cache_error("invalid indexed hash"))
        })
        .transpose()?;
    let coverage = if !good && baseline.is_some() {
        FileCoverage::Stale {
            reason: failure_reason(&parsed.coverage),
            last_good_generation: Generation(baseline.unwrap_or(0)),
            observed_hash: Some(snapshot.content_hash),
            diagnostic: match &parsed.coverage {
                FileCoverage::Failed { error } => Some(error.clone()),
                _ => None,
            },
        }
    } else {
        parsed.coverage.clone()
    };
    let row = if let Some((row, ..)) = &previous {
        *row
    } else {
        execute(
            sql,
            "INSERT INTO files(key,path,path_key,language,indexed_hash,observed_hash,bytes,identity,coverage_json,last_good_generation,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?2,?3,NULL,?4,?5,?6,?7,NULL,0,0,0)",
            params![
                parsed.file.0.as_slice(),
                snapshot.path.as_str(),
                format!("{:?}", parsed.language),
                snapshot.content_hash.0.as_slice(),
                n(snapshot.identity.size),
                serde_json::to_vec(&snapshot.identity).map_err(cache_error)?,
                json(&coverage)?
            ],
        )?;
        value(
            sql,
            "SELECT id FROM files WHERE key=?1",
            [parsed.file.0.as_slice()],
        )?
    };
    if !cold {
        batch::observe_file(sql, parsed.file, &snapshot.path)?;
    }
    let before = if previous.is_some() {
        Some(bindings::fingerprint(sql, row)?)
    } else {
        None
    };
    if good {
        diff::compare(
            sql,
            row,
            &snapshot.path,
            parsed,
            diff::Baseline {
                hash: old_hash,
                reset,
                cold,
            },
            |fact| batch::stage(sql, fact),
        )?;
        let changed = old_hash != Some(parsed.content_hash) || !prior_good;
        if changed {
            invalidate(sql, row, serial)?;
            write::clear_semantics(sql, row)?;
        } else {
            crate::cache::reference_counts::outgoing(sql, row)?;
            execute(sql, "DELETE FROM refs WHERE file=?1", [row])?;
            execute(sql, "DELETE FROM imports WHERE file=?1", [row])?;
        }
        install(sql, row, snapshot, parsed, changed)?;
    } else {
        if prior_good {
            invalidate(sql, row, serial)?;
        }
        crate::cache::reference_counts::outgoing(sql, row)?;
        execute(
            sql,
            "UPDATE refs SET accuracy='NameOnly',target=NULL WHERE file=?1",
            [row],
        )?;
        execute(
            sql,
            "UPDATE imports SET target_symbol=NULL,resolution='NameOnly' WHERE file=?1",
            [row],
        )?;
        if !cold && old_hash != Some(parsed.content_hash) {
            batch::stage(
                sql,
                diff::Fact {
                    file: parsed.file,
                    symbol: None,
                    path: snapshot.path.clone(),
                    span: None,
                    kind: ChangeKind::FileOnly,
                    previous: old_hash,
                    current: Some(parsed.content_hash),
                    baseline_reset: false,
                },
            )?;
        }
    }
    execute(
        sql,
        "UPDATE files SET path=?1,language=?2,indexed_hash=CASE WHEN ?3 THEN ?4 ELSE indexed_hash END,observed_hash=?4,bytes=?5,identity=?6,coverage_json=?7,last_good_generation=CASE WHEN ?3 THEN ?8 ELSE last_good_generation END,last_code_generation=?8,baseline_reset=?9 WHERE id=?10",
        params![
            snapshot.path.as_str(),
            format!("{:?}", parsed.language),
            good,
            snapshot.content_hash.0.as_slice(),
            n(snapshot.identity.size),
            serde_json::to_vec(&snapshot.identity).map_err(cache_error)?,
            json(&coverage)?,
            n(generation),
            reset,
            row
        ],
    )?;
    execute(
        sql,
        "UPDATE meta SET index_generation=?1,observed_serial=max(observed_serial,?2) WHERE singleton=1",
        params![n(generation), n(serial)],
    )?;
    // Re-resolving unchanged importers must converge, including cycles. Source
    // hashes alone miss unchanged re-export text acquiring a new target.
    if before != Some(bindings::fingerprint(sql, row)?) {
        execute(
            sql,
            "INSERT INTO pending_paths(path_key,serial) SELECT DISTINCT f.path_key,?1 FROM import_candidates c JOIN imports i ON i.id=c.import_id JOIN files f ON f.id=i.file WHERE c.path_key=?2 AND f.id<>?3 ON CONFLICT(path_key) DO UPDATE SET serial=max(serial,excluded.serial)",
            params![n(serial), snapshot.path.as_str(), row],
        )?;
    }
    Ok(Applied {
        generation: Generation(generation),
        baseline_reset: reset,
        stale: !good && baseline.is_some(),
    })
}
fn failure_reason(coverage: &FileCoverage) -> CoverageReason {
    match coverage {
        FileCoverage::Deferred { reason } | FileCoverage::Stale { reason, .. } => *reason,
        FileCoverage::Partial { reasons } => reasons
            .first()
            .copied()
            .unwrap_or(CoverageReason::ParseErrors),
        _ => CoverageReason::ReadFailure,
    }
}
pub(super) fn invalidate(sql: &SqlView<'_>, row: i64, serial: u64) -> AtlasResult<()> {
    crate::cache::reference_counts::incoming(sql, row)?;
    execute(
        sql,
        "INSERT INTO pending_paths(path_key,serial) SELECT DISTINCT f.path_key,?1 FROM imports i JOIN files f ON f.id=i.file WHERE i.target_file=?2 AND f.id<>?2 ON CONFLICT(path_key) DO UPDATE SET serial=max(serial,excluded.serial)",
        params![n(serial), row],
    )?;
    execute(
        sql,
        "UPDATE refs SET accuracy='NameOnly',target=NULL WHERE target IN (SELECT id FROM symbols WHERE file=?1)",
        [row],
    )?;
    execute(
        sql,
        "UPDATE imports SET target_symbol=NULL,resolution='NameOnly' WHERE target_file=?1",
        [row],
    )?;
    execute(
        sql,
        "UPDATE imports SET target_symbol=NULL,resolution='NameOnly' WHERE target_symbol IN (SELECT id FROM symbols WHERE file=?1)",
        [row],
    )?;
    Ok(())
}
fn name(sql: &SqlView<'_>, name: &str) -> AtlasResult<i64> {
    execute(sql, "INSERT OR IGNORE INTO names(text) VALUES(?1)", [name])?;
    value(sql, "SELECT id FROM names WHERE text=?1", [name])
}
fn symbol(sql: &SqlView<'_>, id: Option<SymbolId>) -> AtlasResult<Option<i64>> {
    id.map(|id| {
        sql.prepare("SELECT id FROM symbols WHERE key=?1")?
            .query_row([id.0.as_slice()], |r| r.get(0))
            .optional()
            .map_err(cache_error)
    })
    .transpose()
    .map(Option::flatten)
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn install(
    sql: &SqlView<'_>,
    file: i64,
    snapshot: &SourceSnapshot,
    parsed: &ParsedFile,
    replace_symbols: bool,
) -> AtlasResult<()> {
    for record in parsed.symbols.iter().filter(|_| replace_symbols) {
        let name = name(sql, &record.name)?;
        let parent = symbol(sql, record.parent)?;
        if record.parent.is_some() && parent.is_none() {
            return Err(cache_error("symbol parent must precede its child"));
        }
        execute(
            sql,
            "INSERT INTO symbols(key,file,parent,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,signature_hash,body_hash,doc_line,export_alias) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                record.id.0.as_slice(),
                file,
                parent,
                name,
                format!("{:?}", record.kind),
                n(record.span.start_byte),
                n(record.span.end_byte),
                record.span.start.line,
                record.span.start.byte_column,
                record.span.end.line,
                record.span.end.byte_column,
                record.exported,
                record.signature_hash.as_ref().map(|h| h.0.as_slice()),
                record.body_hash.as_ref().map(|h| h.0.as_slice()),
                record.doc_line,
                record.export_alias
            ],
        )?;
        let row: i64 = value(
            sql,
            "SELECT id FROM symbols WHERE key=?1",
            [record.id.0.as_slice()],
        )?;
        execute(
            sql,
            "INSERT INTO symbol_fts(rowid,name,split_name,path,container,doc_line) VALUES(?1,?2,?3,?4,'',?5)",
            params![
                row,
                record.name,
                crate::rank::identifier_index(&record.name),
                snapshot.path.as_str(),
                record.doc_line
            ],
        )?;
    }
    for import in &parsed.imports {
        let local = import
            .local_name
            .as_deref()
            .map(|s| name(sql, s))
            .transpose()?;
        let imported = import
            .imported_name
            .as_deref()
            .map(|s| name(sql, s))
            .transpose()?;
        let target_file = import
            .target_file
            .map(|id| {
                sql.prepare("SELECT id FROM files WHERE key=?1")?
                    .query_row([id.0.as_slice()], |r| r.get::<_, i64>(0))
                    .optional()
                    .map_err(cache_error)
            })
            .transpose()?
            .flatten();
        let target_symbol = symbol(sql, import.target_symbol)?;
        execute(
            sql,
            "INSERT INTO imports(file,spelling,local_name,imported_name,target_file,target_symbol,start_byte,end_byte,resolution,kind,lexical_scope,reexport,wildcard,target_namespace) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                file,
                import.spelling,
                local,
                imported,
                target_file,
                target_symbol,
                n(import.span.start_byte),
                n(import.span.end_byte),
                if target_file.is_some() {
                    "ExplicitImport"
                } else {
                    "NameOnly"
                },
                format!("{:?}", import.kind),
                import.lexical_scope,
                import.reexport,
                import.wildcard,
                import.target_namespace
            ],
        )?;
        let row: i64 = value(sql, "SELECT last_insert_rowid()", [])?;
        for candidate in candidates(&snapshot.path, import)? {
            execute(
                sql,
                "INSERT OR IGNORE INTO import_candidates VALUES(?1,?2)",
                params![row, candidate.as_str()],
            )?;
        }
    }
    for reference in &parsed.references {
        let record = &reference.site;
        let Some(span) = record.site.span else {
            return Err(cache_error("parsed reference has no source span"));
        };
        let enclosing = symbol(sql, record.enclosing)?;
        let target = symbol(sql, record.resolved_target)?;
        let spelling = name(sql, &record.spelling)?;
        let accuracy = if target.is_some() {
            format!("{:?}", record.accuracy)
        } else {
            "NameOnly".into()
        };
        execute(
            sql,
            "INSERT INTO refs(file,enclosing,target,spelling,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,accuracy) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                file,
                enclosing,
                target,
                spelling,
                format!("{:?}", record.kind),
                n(span.start_byte),
                n(span.end_byte),
                span.start.line,
                span.start.byte_column,
                span.end.line,
                span.end.byte_column,
                accuracy
            ],
        )?;
    }
    crate::cache::reference_counts::installed(sql, file)
}
