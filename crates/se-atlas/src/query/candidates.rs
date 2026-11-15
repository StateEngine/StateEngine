use super::*;
use crate::cache::connection::BudgetStatement;

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
    pub downweighted: bool,
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
        admission_time(end)?;
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
        // Close the ID sort before reusing one projected metadata lookup.
        let mut metadata = metadata_statement(sql, plan.kind)?;
        for (rowid, precomputed_last, bm25) in ids {
            if !bm25.is_finite() || bm25 > 0.0 {
                return Err(cache_error("invalid BM25 score"));
            }
            // An unfinished traversal prefix cannot provide a ranked continuation.
            admission_time(end)?;
            let kind = plan.kind;
            let (key, tie, path) = read_metadata(&mut metadata, rowid)?;
            if path.as_ref().is_some_and(crate::policy::built_in_denied) {
                continue;
            }
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
                downweighted: crate::rank::downweight(
                    path.as_ref().map_or(tie.as_str(), |p| p.as_str()),
                    query.kind,
                ),
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
        if candidate.downweighted {
            candidate.activity.score *= 0.5;
        }
    }
    output
        .values
        .sort_by_cached_key(|candidate| super::find::key(candidate, query.order));
    Ok(output)
}
pub(super) fn admission_time(end: Instant) -> AtlasResult<()> {
    if crate::clock::now() < end {
        return Ok(());
    }
    // An expired checkpoint has no allowance left, as in SQL preparation.
    Err(crate::cache::connection::timeout(0))
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
    let mut statement = metadata_statement(sql, kind)?;
    let (key, name, _) = read_metadata(&mut statement, id)?;
    Ok((key, name))
}
fn metadata_statement<'a>(sql: &'a SqlView<'_>, kind: Kind) -> AtlasResult<BudgetStatement<'a>> {
    let statement = match kind {
        Kind::Symbol => {
            "SELECT s.key,n.text,f.path FROM symbols s JOIN names n ON n.id=s.name JOIN files f ON f.id=s.file WHERE s.id=?1"
        }
        Kind::File => "SELECT key,path,path FROM files WHERE id=?1",
        Kind::Record => "SELECT CAST(record_id AS BLOB),record_id,NULL FROM records WHERE id=?1",
        Kind::Commit => "SELECT oid,hex(oid),NULL FROM commits WHERE id=?1",
    };
    sql.prepare(statement)
}
fn read_metadata(
    statement: &mut BudgetStatement<'_>,
    id: i64,
) -> AtlasResult<(Vec<u8>, String, Option<RelativePath>)> {
    let mut rows = statement.query([id]).map_err(cache_error)?;
    let row = rows
        .next()
        .map_err(cache_error)?
        .ok_or_else(|| cache_error("candidate disappeared in snapshot"))?;
    let path = get::<Option<String>>(row, 2)?
        .map(RelativePath::new)
        .transpose()?;
    Ok((get(row, 0)?, get(row, 1)?, path))
}
