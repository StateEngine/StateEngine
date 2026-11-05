//! Resumable coverage counts. The graph writer must remain serialized until
//! completion; record-feed writes may continue because they do not alter it.
//! Each transaction visits at most 64 files or 1024 references by primary key.
use crate::{
    cache::connection::{CacheConnection, SqlView},
    errors::{AtlasResult, cache_error},
    model::{Coverage, CoverageReason, FileCoverage},
};
use std::time::Instant;

#[derive(Clone, Default)]
pub struct CoverageScan {
    after: i64,
    phase: Phase,
    files: u64,
    indexed: u64,
    partial: u64,
    deferred: u64,
    failed: u64,
    first_failure: Option<se_types::ErrorBody>,
    stale: u64,
    resolved: u64,
    name_only: u64,
    reasons: Vec<CoverageReason>,
}
#[derive(Clone, Copy, Default)]
enum Phase {
    #[default]
    Files,
    References,
    Done,
}
impl CoverageScan {
    /// No cursor or partial counts escape a failed transaction. No statement,
    /// snapshot, row inventory or connection is retained between calls.
    pub fn step(&mut self, db: &CacheConnection<'_>, deadline: Instant) -> AtlasResult<bool> {
        let next = db.read(deadline, |sql| {
            let mut next = self.clone();
            next.advance(sql)?;
            Ok(next)
        })?;
        *self = next;
        Ok(matches!(self.phase, Phase::Done))
    }

    fn advance(&mut self, sql: &SqlView<'_>) -> AtlasResult<()> {
        match self.phase {
            Phase::Files => {
                let mut statement = sql.prepare(
                    "SELECT id,coverage_json FROM files WHERE id>?1 ORDER BY id LIMIT 64",
                )?;
                let mut rows = statement.query([self.after]).map_err(cache_error)?;
                let mut count = 0;
                while let Some(row) = rows.next().map_err(cache_error)? {
                    let value: FileCoverage =
                        serde_json::from_str(&row.get::<_, String>(1).map_err(cache_error)?)
                            .map_err(cache_error)?;
                    match value {
                        FileCoverage::Indexed => self.indexed += 1,
                        FileCoverage::Partial { reasons } => {
                            self.partial += 1;
                            for reason in reasons {
                                self.reason(reason);
                            }
                        }
                        FileCoverage::Deferred { reason } => {
                            self.deferred += 1;
                            self.reason(reason);
                        }
                        FileCoverage::Failed { error } => {
                            self.failed += 1;
                            if self.first_failure.is_none() {
                                self.first_failure = Some(error);
                            }
                        }
                        FileCoverage::Stale { reason, .. } => {
                            self.stale += 1;
                            self.reason(reason);
                        }
                    }
                    self.after = row.get(0).map_err(cache_error)?;
                    self.files += 1;
                    count += 1;
                }
                if count < 64 {
                    self.phase = Phase::References;
                    self.after = 0;
                }
            }
            Phase::References => {
                // New epochs create refs_coverage before ingestion. Older
                // schema-3 epochs can use their bounded primary-key range too.
                let mut statement = sql.prepare(
                    "SELECT id,target IS NOT NULL,accuracy='NameOnly' FROM refs WHERE id>?1 ORDER BY id LIMIT 1024",
                )?;
                let mut rows = statement.query([self.after]).map_err(cache_error)?;
                let mut count = 0;
                while let Some(row) = rows.next().map_err(cache_error)? {
                    self.resolved += u64::from(row.get::<_, bool>(1).map_err(cache_error)?);
                    self.name_only += u64::from(row.get::<_, bool>(2).map_err(cache_error)?);
                    self.after = row.get(0).map_err(cache_error)?;
                    count += 1;
                }
                if count < 1024 {
                    if let Some(reason) = crate::history::limitation(sql)? {
                        self.reason(reason);
                    }
                    self.phase = Phase::Done;
                }
            }
            Phase::Done => (),
        }
        Ok(())
    }

    pub fn apply(&self, coverage: &mut Coverage) -> AtlasResult<()> {
        if !matches!(self.phase, Phase::Done) {
            return Err(cache_error("coverage scan is incomplete"));
        }
        coverage.discovered_files = self.files;
        coverage.indexed_files = self.indexed;
        coverage.partial_files = self.partial;
        coverage.deferred_files = self.deferred;
        coverage.failed_files = self.failed;
        coverage.stale_files = self.stale;
        coverage.resolved_references = self.resolved;
        coverage.name_only_references = self.name_only;
        coverage.reasons.clone_from(&self.reasons);
        Ok(())
    }

    /// One observed failure in stable file order; later maintenance refusals
    /// must not hide why the published coverage is incomplete.
    pub fn first_failure(&self) -> Option<&se_types::ErrorBody> {
        self.first_failure.as_ref()
    }

    fn reason(&mut self, reason: CoverageReason) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}
