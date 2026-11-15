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
        // Reuse one small metadata statement after the bounded ID sort has
        // closed. Full symbol spans, parents and file coverage are needed only
        // when a winning hit is materialized, not for every admitted identity.
        let kind = plan.kind;
        let mut metadata = sql.prepare(admission_metadata(kind))?;
        for (rowid, precomputed_last, bm25) in ids {
            admission_time(end)?;
            if !bm25.is_finite() || bm25 > 0.0 {
                return Err(cache_error("invalid BM25 score"));
            }
            let (key, tie, path) = read_metadata(&mut metadata, kind, rowid)?;
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
            let downweighted = crate::rank::downweight(
                path.as_ref().map_or(tie.as_str(), |p| p.as_str()),
                query.kind,
            );
            let candidate = Candidate {
                kind,
                rowid,
                tier: plan.tier,
                key,
                tie,
                activity: crate::rank::Activity::default(),
                precomputed_last,
                lexical: if bm25 < 0.0 { -bm25 } else { 0.0 },
                related: false,
                downweighted,
            };
            admit(&mut output, &mut resident, candidate)?;
        }
    }
    rank(&mut output, env, sql, snapshot, query)?;
    Ok(output)
}
fn read_metadata(
    metadata: &mut BudgetStatement<'_>,
    kind: Kind,
    rowid: i64,
) -> AtlasResult<(Vec<u8>, String, Option<RelativePath>)> {
    let mut rows = metadata.query([rowid]).map_err(cache_error)?;
    let row = rows
        .next()
        .map_err(cache_error)?
        .ok_or_else(|| cache_error("candidate disappeared in snapshot"))?;
    let path = get::<Option<String>>(row, 2)?
        .map(RelativePath::new)
        .transpose()?;
    if matches!(kind, Kind::Symbol | Kind::File) && path.is_none() {
        return Err(cache_error("candidate file disappeared in snapshot"));
    }
    Ok((get(row, 0)?, get(row, 1)?, path))
}

fn admit(output: &mut Candidates, resident: &mut usize, candidate: Candidate) -> AtlasResult<()> {
    *resident += candidate.key.len() + candidate.tie.len() + 160;
    let position = output.values.partition_point(|old| {
        old.tier
            .cmp(&candidate.tier)
            .then(candidate.precomputed_last.cmp(&old.precomputed_last))
            .then(old.tie.cmp(&candidate.tie))
            .then(old.key.cmp(&candidate.key))
            .is_le()
    });
    output.values.insert(position, candidate);
    while output.values.len() > 128 || *resident > 24576 {
        let old = output
            .values
            .pop()
            .ok_or_else(|| cache_error("candidate admission underflow"))?;
        *resident -= old.key.len() + old.tie.len() + 160;
        output.truncated = true;
    }
    Ok(())
}

fn rank(
    output: &mut Candidates,
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    query: &FindQuery,
) -> AtlasResult<()> {
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
    Ok(())
}

fn admission_metadata(kind: Kind) -> &'static str {
    match kind {
        Kind::Symbol => {
            "SELECT s.key,n.text,f.path FROM symbols s JOIN names n ON n.id=s.name LEFT JOIN files f ON f.id=s.file WHERE s.id=?1"
        }
        Kind::File => "SELECT key,path,path FROM files WHERE id=?1",
        Kind::Record => "SELECT CAST(record_id AS BLOB),record_id,NULL FROM records WHERE id=?1",
        Kind::Commit => "SELECT oid,hex(oid),NULL FROM commits WHERE id=?1",
    }
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
