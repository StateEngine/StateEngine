use super::*;
pub(super) fn get(
    connection: &mut CacheConnection<'_>,
    root: &Root,
    watched: usize,
    counts: Option<&se_atlas::coverage::CoverageScan>,
    deadline: Instant,
) -> AtlasResult<IndexSummary> {
    let complete = counts.is_some();
    let project = connection.identity().scope.registration.project.clone();
    let epoch = connection.identity().epoch.clone();
    connection.write(65536, deadline, |sql| {
        let (generation, json, prior): (i64, String, String) = sql
            .prepare("SELECT index_generation,coverage_json,state_json FROM meta WHERE singleton=1")?
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
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
        let failure = if coverage.failed_files > 0 || coverage.stale_files > 0 {
            match counts {
                Some(counts) => counts.first_failure().cloned(),
                None => match serde_json::from_str(&prior).map_err(sql_error)? {
                    IndexState::Partial { error } => Some(error),
                    _ => None,
                },
            }
        } else { None };
        let state = if let Some(error) = failure {
            IndexState::Partial { error }
        } else if complete && (root.unwatched > 0 || !coverage.watch_discovery_complete) {
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
            project,
            root: root.id.clone(), epoch: Some(epoch),
            generation: Some(Generation(u64::try_from(generation).map_err(sql_error)?)), state, coverage,
        })
    })
}
