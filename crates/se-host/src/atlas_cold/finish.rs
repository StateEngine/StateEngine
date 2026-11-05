use super::*;

/// Persist the limitation on each remaining parsed file so later coverage
/// scans cannot erase it. Failed/deferred/stale observations keep their cause.
pub(super) fn limited_resolution(
    db: &CacheConnection<'_>,
    mut after: i64,
    job_deadline: Instant,
) -> AtlasResult<()> {
    loop {
        let next = db.write(2_000_000, job_deadline, |sql| {
            let mut statement =
                sql.prepare("SELECT id,coverage_json FROM files WHERE id>?1 ORDER BY id LIMIT 64")?;
            let mut rows = statement.query([after]).map_err(failure)?;
            let mut last = None;
            while let Some(row) = rows.next().map_err(failure)? {
                let id: i64 = row.get(0).map_err(failure)?;
                let value: FileCoverage =
                    serde_json::from_str(&row.get::<_, String>(1).map_err(failure)?)
                        .map_err(failure)?;
                last = Some(id);
                let mut reasons = match value {
                    FileCoverage::Indexed => Vec::new(),
                    FileCoverage::Partial { reasons } => reasons,
                    _ => continue,
                };
                if !reasons.contains(&CoverageReason::TimeLimit) {
                    reasons.push(CoverageReason::TimeLimit);
                }
                sql.prepare("UPDATE files SET coverage_json=?1 WHERE id=?2")?
                    .execute((
                        serde_json::to_string(&FileCoverage::Partial { reasons })
                            .map_err(failure)?,
                        id,
                    ))
                    .map_err(failure)?;
            }
            Ok(last)
        })?;
        let Some(last) = next else { return Ok(()) };
        after = last;
        if !db.checkpoint(job_deadline)? {
            return Err(failure("partial cold epoch checkpoint remains busy"));
        }
        db.release_cold_memory(job_deadline)?;
    }
}

pub(super) fn finish(
    db: &CacheConnection<'_>,
    mut coverage: Coverage,
    job_deadline: Instant,
) -> AtlasResult<IndexSummary> {
    let mut scan = se_atlas::coverage::CoverageScan::default();
    while !scan.step(db, job_deadline)? {}
    scan.apply(&mut coverage)?;
    if !coverage.discovery_complete && !coverage.reasons.contains(&CoverageReason::TimeLimit) {
        coverage.reasons.push(CoverageReason::TimeLimit);
    }
    // Discovery completion is not Current: the parent's dirty serial fence
    // and renewal replay still have to run after adoption.
    let state = IndexState::VerificationNeeded {
        reason: if coverage.discovery_complete {
            CoverageReason::StaleSnapshot
        } else {
            CoverageReason::TimeLimit
        },
    };
    let generation = db.write(131072, job_deadline, |sql| {
        let generation: i64 = sql
            .prepare("SELECT index_generation FROM meta WHERE singleton=1")?
            .query_row([], |r| r.get(0))
            .map_err(failure)?;
        sql.prepare("UPDATE meta SET coverage_json=?1,state_json=?2,discovery_complete=?3,published_generation=index_generation WHERE singleton=1")?
            .execute((
                serde_json::to_string(&coverage).map_err(failure)?,
                serde_json::to_string(&state).map_err(failure)?,
                coverage.discovery_complete,
            ))
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
