use super::*;
pub(super) fn get(
    connection: &CacheConnection<'_>,
    root: &Root,
    watched: usize,
    counts: Option<&se_atlas::coverage::CoverageScan>,
    deadline: Instant,
) -> AtlasResult<IndexSummary> {
    let complete = counts.is_some();
    connection.write(65536, deadline, |sql| {
        let (generation, json): (i64, String) = sql
            .prepare("SELECT index_generation,coverage_json FROM meta WHERE singleton=1")?
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(sql_error)?;
        let mut coverage: Coverage = serde_json::from_str(&json).map_err(sql_error)?;
        if let Some(counts) = counts {
            counts.apply(&mut coverage)?;
        }
        coverage.watched_directories = watched as u64;
        coverage.unwatched_directories = root.unwatched;
        coverage.watch_discovery_complete = root.discovery_complete && root.native.as_ref()
            .and_then(|n| n.metadata.as_ref()).is_none_or(|m| m.discovery_complete);
        coverage.discovery_complete = root.discovery_complete;
        coverage.watch_stats_started = root.started;
        coverage.watch_activation_attempts = root.attempts;
        coverage.watch_limited_activations = root.limited;
        for reason in &root.reasons {
            if !coverage.reasons.contains(reason) {
                coverage.reasons.push(*reason);
            }
        }
        let pending: u32 = sql.prepare("SELECT count(*) FROM active_batch")?
            .query_row([], |r| r.get(0)).map_err(sql_error)?;
        let state = if complete && (root.unwatched > 0 || !coverage.watch_discovery_complete) {
            IndexState::VerificationNeeded { reason: CoverageReason::PartialWatch }
        } else if !complete || pending > 0 {
            IndexState::Updating { pending_files: if complete { 0 } else { 1 },
                pending_change_batches: pending, discovery_complete: root.discovery_complete }
        } else { IndexState::Current };
        sql.prepare("UPDATE meta SET coverage_json=?1,state_json=?2,discovery_complete=?3 WHERE singleton=1")?
            .execute((serde_json::to_string(&coverage).map_err(sql_error)?,
                serde_json::to_string(&state).map_err(sql_error)?, root.discovery_complete))
            .map_err(sql_error)?;
        Ok(IndexSummary {
            memory: None,
            project: connection.identity().scope.registration.project.clone(),
            root: root.id.clone(), epoch: Some(connection.identity().epoch.clone()),
            generation: Some(Generation(u64::try_from(generation).map_err(sql_error)?)), state, coverage,
        })
    })
}
