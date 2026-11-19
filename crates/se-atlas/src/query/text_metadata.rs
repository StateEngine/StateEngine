//! Metadata and live-source hits share one ordered, bounded search window.
use super::*;
pub(super) struct Metadata {
    pub values: Vec<(SearchHit, Key)>,
    pub truncated: bool,
}
pub(super) fn collect(
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    query: &FindQuery,
    mode: SearchMode,
    end: Instant,
) -> AtlasResult<Metadata> {
    // Metadata still has the short SQL budget; text uses the remaining scan budget.
    let started = crate::clock::now();
    let metadata_end = end.min(started + query.budget.work);
    let result = super::phase_timeout(
        "combined metadata candidates",
        started,
        metadata_end,
        super::candidates::collect(env, sql, snapshot, query, mode, metadata_end),
    );
    eprintln!("ATLAS_QUERY_METADATA mode={mode:?} budget_us={} elapsed_us={} ok={}", metadata_end.saturating_duration_since(started).as_micros(), started.elapsed().as_micros(), result.is_ok());
    let candidates = result?;
    let mut output = Metadata {
        values: Vec::new(),
        truncated: candidates.truncated,
    };
    let mut bytes = 0;
    for candidate in candidates.values {
        let Some(mut hit) = super::find::materialize(env, sql, snapshot, &candidate, query, mode)?
        else {
            continue;
        };
        if query.full {
            hit.body = match &mut hit.target {
                HitTarget::Code(code) => super::body::source(env, &mut code.pointer, end)?,
                HitTarget::Record(record) => match env.records.body(
                    &snapshot.index.project,
                    env.viewer,
                    &record.pointer,
                    Some(&query.query),
                )? {
                    Read::Present { value } => Some(value),
                    Read::Absent { .. } => None,
                    Read::Unknown { what } => return Err(cache_error(what)),
                    Read::Unreadable { source, reason, .. } => {
                        return Err(cache_error(format!("{source}: {reason}")));
                    }
                },
                HitTarget::Commit(_) => None,
            };
        }
        bytes += size(&hit)?;
        if bytes > 24576 {
            output.truncated = true;
            break;
        }
        output
            .values
            .push((hit, super::find::key(&candidate, query.order)));
    }
    Ok(output)
}
