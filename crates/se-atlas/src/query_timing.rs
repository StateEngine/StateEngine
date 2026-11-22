//! Bounded query phases and their SQL timeout diagnostics.
use super::*;

fn minimum_phase(work: Duration) -> Duration {
    (work / 8).clamp(Duration::from_nanos(1), Duration::from_millis(5))
}
/// Add the actual phase allowance and elapsed time to a generic SQL timeout.
pub(super) fn phase_timeout<T>(
    phase: &str,
    started: Instant,
    end: Instant,
    result: AtlasResult<T>,
) -> AtlasResult<T> {
    result.map_err(|error| phase_error(phase, started, end, error))
}
fn phase_error(
    phase: &str,
    started: Instant,
    end: Instant,
    mut error: se_types::SeError,
) -> se_types::SeError {
    if let se_types::Detail::DeadlineExceeded(detail) = error.body.detail()
        && detail.op.starts_with("Atlas SQL")
    {
        let stage = detail.op.strip_prefix("Atlas SQL").unwrap_or("").trim();
        let label = if stage.is_empty() {
            phase.to_owned()
        } else {
            format!("{phase}: {stage}")
        };
        error.body = crate::cache::connection::timeout_phase(
            &label,
            end.saturating_duration_since(started),
            crate::clock::now().saturating_duration_since(started),
        )
        .body;
    }
    error
}
pub(super) fn collect_phase(
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    query: &FindQuery,
    mode: SearchMode,
    window: (Instant, Instant),
) -> AtlasResult<super::candidates::Candidates> {
    let candidate_end = window.1 - (query.budget.work / 4).min(Duration::from_millis(3));
    let started = crate::clock::now();
    if candidate_end.saturating_duration_since(started) < minimum_phase(query.budget.work) {
        return phase_timeout(
            "metadata search before candidate admission",
            window.0,
            window.1,
            Err(crate::cache::connection::timeout(0)),
        );
    }
    phase_timeout(
        "metadata candidates",
        started,
        candidate_end,
        super::candidates::collect(env, sql, snapshot, query, mode, candidate_end),
    )
}
