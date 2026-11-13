use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Kind {
    Symbol,
    File,
    Record,
    Commit,
}
pub(super) struct Candidate {
    pub kind: Kind,
    pub rowid: i64,
    pub tier: u8,
    pub key: Vec<u8>,
    pub activity: crate::rank::Activity,
    pub tie: String,
    pub precomputed_last: Option<i64>,
    pub lexical: f64,
    pub related: bool,
}
pub(super) struct Candidates {
    pub values: Vec<Candidate>,
    pub truncated: bool,
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn collect(
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    query: &FindQuery,
    mode: SearchMode,
    end: Instant,
) -> AtlasResult<Candidates> {
    if mode == SearchMode::Related {
        return super::related::collect(env, sql, snapshot, query, end);
    }
    let mut output = Candidates {
        values: Vec::with_capacity(128),
        truncated: false,
    };
    let mut resident = 0;
    for plan in super::candidate_sql::plans(query, mode)? {
        if crate::clock::now() >= end {
            output.truncated = true;
            break;
        }
        let mut ids = Vec::with_capacity(513);
        {
            let mut stmt = sql.prepare(&plan.sql)?;
            let mut rows = stmt
                .query(rusqlite::params_from_iter(plan.values))
                .map_err(cache_error)?;
            while let Some(row) = rows.next().map_err(cache_error)? {
                ids.push((
                    get::<i64>(row, 0)?,
                    get::<Option<i64>>(row, 1)?,
                    if plan.lexical {
                        get::<f64>(row, 2)?
                    } else {
                        0.0
                    },
                ));
            }
        }
        if ids.len() > 512 {
            ids.pop();
            output.truncated = true;
        }
        for (rowid, precomputed_last, bm25) in ids {
            if !bm25.is_finite() || bm25 > 0.0 {
                return Err(cache_error("invalid BM25 score"));
            }
            if crate::clock::now() >= end {
                output.truncated = true;
                break;
            }
            let kind = plan.kind;
            if matches!(kind, Kind::Symbol | Kind::File) {
                let file = if kind == Kind::Symbol {
                    symbol_by_id(sql, rowid)?.1
                } else {
                    rowid
                };
                if crate::policy::built_in_denied(&file_by_id(sql, file)?.pointer.path) {
                    continue;
                }
            }
            let (key, tie) = metadata(sql, kind, rowid)?;
            if key.len() > 256 || tie.len() > 4096 || tie.contains('\0') {
                return Err(cache_error("search candidate exceeds key/name admission"));
            }
            if kind == Kind::Symbol
                && plan.tier == 2
                && !crate::rank::split_matches(&tie, query.query.as_str())
            {
                continue;
            }
            if kind == Kind::Record {
                let pointer = record_pointer(sql, rowid)?;
                let visible = if mode == SearchMode::Literal {
                    env.records.literal_read(
                        &snapshot.index.project,
                        env.viewer,
                        &pointer,
                        &query.query,
                    )?
                } else {
                    env.records.read(
                        &snapshot.index.project,
                        env.viewer,
                        &pointer,
                        Some(&query.query),
                    )?
                };
                match visible {
                    Read::Present { value } if value.pointer == pointer => (),
                    Read::Absent { .. } => continue,
                    _ => return Err(cache_error("search record authority unavailable")),
                }
            }
            if output
                .values
                .iter()
                .any(|c| c.kind == kind && c.rowid == rowid)
            {
                continue;
            }
            let cost = key.len() + tie.len() + 160;
            resident += cost;
            output.values.push(Candidate {
                kind,
                rowid,
                tier: plan.tier,
                key,
                tie,
                activity: crate::rank::Activity::default(),
                precomputed_last,
                lexical: if bm25 < 0.0 { -bm25 } else { 0.0 },
                related: false,
            });
            output.values.sort_by(|a, b| {
                a.tier
                    .cmp(&b.tier)
                    .then(b.precomputed_last.cmp(&a.precomputed_last))
                    .then(a.tie.cmp(&b.tie))
                    .then(a.key.cmp(&b.key))
            });
            while output.values.len() > 128 || resident > 24576 {
                let old = output
                    .values
                    .pop()
                    .ok_or_else(|| cache_error("candidate admission underflow"))?;
                resident -= old.key.len() + old.tie.len() + 160;
                output.truncated = true;
            }
        }
    }
    for candidate in &mut output.values {
        let tag = match candidate.kind {
            Kind::Symbol => "symbol",
            Kind::File => "file",
            Kind::Record => "record",
            Kind::Commit => "commit",
        };
        candidate.activity = crate::rank::activity(
            sql,
            tag,
            &candidate.key,
            crate::rank::ActivityQuery {
                project: &snapshot.index.project,
                viewer: env.viewer,
                records: env.records,
                now: env.now_unix_ms,
            },
        )?;
        let path = if candidate.kind == Kind::Symbol {
            let file_id = symbol_by_id(sql, candidate.rowid)?.1;
            Some(file_by_id(sql, file_id)?.pointer.path)
        } else {
            None
        };
        if crate::rank::downweight(
            path.as_ref().map_or(candidate.tie.as_str(), |p| p.as_str()),
            query.kind,
        ) {
            candidate.activity.score *= 0.5;
        }
    }
    output
        .values
        .sort_by_cached_key(|candidate| super::find::key(candidate, query.order));
    Ok(output)
}
pub(super) fn record_pointer(sql: &SqlView<'_>, id: i64) -> AtlasResult<RecordPointer> {
    let mut stmt = sql.prepare("SELECT record_id,kind,source_event FROM records WHERE id=?1")?;
    let mut rows = stmt.query([id]).map_err(cache_error)?;
    let row = rows
        .next()
        .map_err(cache_error)?
        .ok_or_else(|| cache_error("record candidate disappeared in a snapshot"))?;
    Ok(RecordPointer {
        key: RecordKey::new(get::<String>(row, 0)?)?,
        kind: tag(get(row, 1)?)?,
        source_event: get::<String>(row, 2)?.parse()?,
    })
}

pub(super) fn metadata(sql: &SqlView<'_>, kind: Kind, id: i64) -> AtlasResult<(Vec<u8>, String)> {
    let statement = match kind {
        Kind::Symbol => {
            "SELECT s.key,n.text FROM symbols s JOIN names n ON n.id=s.name WHERE s.id=?1"
        }
        Kind::File => "SELECT key,path FROM files WHERE id=?1",
        Kind::Record => "SELECT CAST(record_id AS BLOB),record_id FROM records WHERE id=?1",
        Kind::Commit => "SELECT oid,hex(oid) FROM commits WHERE id=?1",
    };
    let mut stmt = sql.prepare(statement)?;
    let mut rows = stmt.query([id]).map_err(cache_error)?;
    let row = rows
        .next()
        .map_err(cache_error)?
        .ok_or_else(|| cache_error("candidate disappeared in snapshot"))?;
    Ok((get(row, 0)?, get(row, 1)?))
}
