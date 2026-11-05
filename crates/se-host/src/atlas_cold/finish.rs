use super::*;
pub(super) fn finish(
    db: &CacheConnection<'_>,
    mut coverage: Coverage,
    job_deadline: Instant,
) -> AtlasResult<IndexSummary> {
    let mut scan = se_atlas::coverage::CoverageScan::default();
    while !scan.step(db, sql_deadline().min(job_deadline))? {}
    scan.apply(&mut coverage)?;
    // Discovery completion is not Current: the parent's dirty serial fence
    // and renewal replay still have to run after adoption.
    let state = IndexState::VerificationNeeded {
        reason: CoverageReason::StaleSnapshot,
    };
    let generation = db.write(131072, sql_deadline().min(job_deadline), |sql| {
        let generation: i64 = sql
            .prepare("SELECT index_generation FROM meta WHERE singleton=1")?
            .query_row([], |r| r.get(0))
            .map_err(failure)?;
        sql.prepare("UPDATE meta SET coverage_json=?1,state_json=?2,discovery_complete=1,published_generation=index_generation WHERE singleton=1")?
            .execute([
                serde_json::to_string(&coverage).map_err(failure)?,
                serde_json::to_string(&state).map_err(failure)?,
            ])
            .map_err(failure)?;
        Ok(Generation(generation.try_into().map_err(failure)?))
    })?;
    let id = db.identity();
    Ok(IndexSummary {
        memory: None,
        project: id.scope.registration.project.clone(),
        root: id.scope.registration.root.clone(),
        epoch: Some(id.epoch.clone()),
        generation: Some(generation),
        state,
        coverage,
    })
}
