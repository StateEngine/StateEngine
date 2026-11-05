//! Parent-side typed protocol and post-reap adoption. No child output grants a pointer write.
use super::*;
use std::path::Path;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub struct ColdJob {
    worker: se_proc::atlas_worker::AtlasWorker,
    pub request: protocol::Request,
    expected: Option<Vec<u8>>,
    history: Option<super::history::Plan>,
    deadline: Instant,
    completion: Option<IndexSummary>,
    completed: u64,
    discovered: u64,
    last_path: Option<RelativePath>,
    last_phase: protocol::Phase,
    pub peak_observed_bytes: u64,
}
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
impl ColdJob {
    pub fn spawn(image: &Path, request: protocol::Request) -> AtlasResult<Self> {
        Self::spawn_planned(image, request, None)
    }
    pub fn spawn_with_history(
        image: &Path,
        mut request: protocol::Request,
        metadata: GitMetadataRegistration,
        profile: Option<&SqlProfile>,
    ) -> AtlasResult<Self> {
        let history = match super::history::Plan::new(metadata, profile) {
            Ok(plan) => Some(plan),
            Err(error) => {
                request.history_unavailable = Some(error.body);
                None
            }
        };
        Self::spawn_planned(image, request, history)
    }
    fn spawn_planned(
        image: &Path,
        request: protocol::Request,
        history: Option<super::history::Plan>,
    ) -> AtlasResult<Self> {
        request.validate()?;
        let source = request.source()?;
        let cache = NativeAtlasCache::open(&request.home.to_local()?, source.scope.clone())?;
        let expected = cache
            .as_ref()
            .map(|c| c.read_pointer())
            .transpose()?
            .flatten();
        let epoch = expected
            .as_ref()
            .map(|b| pointer::decode(b, &source.scope).map(|p| p.epoch))
            .transpose()?;
        if epoch != request.expected_epoch {
            return Err(failure("expected cold epoch is stale before spawn"));
        }
        let deadline = Instant::now() + Duration::from_secs(900);
        let worker = se_proc::atlas_worker::AtlasWorker::spawn(
            image,
            &serde_json::to_vec(&request).map_err(failure)?,
            deadline,
        )
        .map_err(failure)?;
        Ok(Self {
            worker,
            request,
            expected,
            history,
            deadline,
            completion: None,
            completed: 0,
            discovered: 0,
            last_path: None,
            last_phase: protocol::Phase::Startup,
            peak_observed_bytes: 0,
        })
    }
    pub fn pid(&self) -> u32 {
        self.worker.pid()
    }
    pub fn wait_ready(&mut self, deadline: Instant) -> AtlasResult<bool> {
        self.worker
            .wait_ready(deadline)
            .map_err(|error| self.native_failure(error))
    }
    #[cfg(unix)]
    pub fn readiness_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.worker.readiness_fd()
    }
    pub fn cancel(&mut self) -> AtlasResult<()> {
        self.worker.cancel().map_err(failure)
    }
    fn native_failure(&mut self, reason: impl std::fmt::Display) -> SeError {
        let stderr = self.stderr_report();
        SeError::new(se_types::Detail::AtlasUnreadable(
            se_types::details::AtlasUnreadable {
                path: self
                    .last_path
                    .as_ref()
                    .map_or("<registered root>", |p| p.as_str())
                    .into(),
                reason: format!(
                    "{reason}; last_phase={:?}; cold_memory_limit={}; {}; prior pointer preserved",
                    self.last_phase,
                    se_proc::atlas_worker::MEMORY_BYTES,
                    stderr
                ),
            },
        ))
    }
    pub fn poll(&mut self) -> AtlasResult<Option<IndexSummary>> {
        while let Some(bytes) = self
            .worker
            .receive()
            .map_err(|error| self.native_failure(format!("cold channel failure: {error}")))?
        {
            let reply: protocol::Reply = serde_json::from_slice(&bytes).map_err(failure)?;
            match reply {
                protocol::Reply::Working { job, path, phase } => {
                    if job != self.request.job {
                        self.cancel()?;
                        return Err(failure("foreign cold phase report"));
                    }
                    if let Some(path) = path {
                        self.last_path = Some(path);
                    }
                    self.last_phase = phase;
                }
                protocol::Reply::Progress {
                    job,
                    discovered,
                    completed,
                } => {
                    if job != self.request.job
                        || discovered < self.discovered
                        || completed < self.completed
                        || discovered > u64::from(self.request.max_files)
                        || completed > u64::from(self.request.max_files) * 2
                    {
                        self.cancel()?;
                        return Err(failure(
                            "cold progress does not match the one-use job/bounds",
                        ));
                    }
                    self.discovered = discovered;
                    self.completed = completed;
                    self.peak_observed_bytes = self.worker.observe_memory().map_err(failure)?;
                }
                protocol::Reply::Completed { job, summary } => {
                    if self.completion.is_some()
                        || job != self.request.job
                        || summary.project != self.request.project
                        || summary.root != self.request.root
                        || summary.epoch.as_ref() != Some(&self.request.epoch)
                        || (!summary.coverage.discovery_complete
                            && (!summary
                                .coverage
                                .reasons
                                .contains(&CoverageReason::TimeLimit)
                                || !matches!(
                                    &summary.state,
                                    IndexState::VerificationNeeded {
                                        reason: CoverageReason::TimeLimit
                                    }
                                )))
                    {
                        self.cancel()?;
                        return Err(failure(
                            "cold completion does not match job/root/epoch or explicit partial discovery",
                        ));
                    }
                    self.completion = Some(*summary);
                    self.worker.acknowledge_completion().map_err(failure)?;
                    self.peak_observed_bytes = self.worker.peak_observed_bytes();
                }
                protocol::Reply::Failed { job, error } => {
                    // The runtime retains custody and performs exact cleanup.
                    // Return the worker's original reason before cleanup can fail.
                    let error = if job == self.request.job {
                        SeError::from(error)
                    } else {
                        failure("foreign failed cold job")
                    };
                    return Err(self.native_failure(&error).with_cause(error));
                }
            }
        }
        let Some(status) = self
            .worker
            .try_reap()
            .map_err(|error| self.native_failure(error))?
        else {
            return Ok(None);
        };
        if !status.success() {
            return Err(self.native_failure(format!("cold child exited {status}")));
        }
        let mut summary = self
            .completion
            .take()
            .ok_or_else(|| failure("cold child reaped without complete protocol"))?;
        let source = self.request.source()?;
        let scope = source.scope.clone();
        let cache = NativeAtlasCache::resume_unpublished(
            &self.request.home.to_local()?,
            scope.clone(),
            &self.request.epoch,
        )?;
        if cache.read_pointer()? != self.expected {
            return Err(failure("old epoch changed before cold adoption"));
        }
        let profile = SqlProfile::contained_cold();
        let candidate = CacheConnection::open(
            &cache,
            CacheIdentity {
                scope: scope.clone(),
                epoch: self.request.epoch.clone(),
            },
            ConnectionRole::CandidateWriter,
            &profile,
            // Full integrity traverses the captured graph after exact reap.
            // It belongs to the remaining job clock, not a query allowance.
            self.deadline,
        )?
        .ok_or_else(|| failure("staged candidate disappeared"))?;
        let actual = metadata(&candidate, &self.request, self.deadline)?;
        if actual != summary {
            return Err(failure(
                "child summary differs from independently reopened candidate",
            ));
        }
        let candidate = if let Some(history) = self.history.take() {
            drop(candidate);
            let (generation, unavailable) = history.seed(&cache, &self.request, self.deadline)?;
            summary.generation = Some(generation);
            if let Some(diagnostic) = unavailable {
                summary.coverage.history_unavailable = Some(diagnostic);
                if !summary
                    .coverage
                    .reasons
                    .contains(&CoverageReason::HistoryUnavailable)
                {
                    summary
                        .coverage
                        .reasons
                        .push(CoverageReason::HistoryUnavailable);
                }
                summary.state = IndexState::VerificationNeeded {
                    reason: CoverageReason::HistoryUnavailable,
                };
            }
            let candidate = CacheConnection::open(
                &cache,
                CacheIdentity {
                    scope: scope.clone(),
                    epoch: self.request.epoch.clone(),
                },
                ConnectionRole::CandidateWriter,
                &profile,
                self.deadline,
            )?
            .ok_or_else(|| failure("staged candidate disappeared after history"))?;
            if metadata(&candidate, &self.request, self.deadline)? != summary {
                return Err(failure("history candidate differs before publication"));
            }
            candidate
        } else {
            candidate
        };
        pointer::publish(&cache, &candidate, self.expected.as_deref(), self.deadline)?;
        drop(candidate);
        drop(cache);
        let readback = NativeAtlasCache::open(&self.request.home.to_local()?, scope.clone())?
            .ok_or_else(|| failure("published cache missing on readback"))?;
        let reopened = pointer::open_current(
            &readback,
            &scope,
            ConnectionRole::ExternalReader,
            &profile,
            self.deadline,
        )?
        .ok_or_else(|| failure("published epoch missing on independent readback"))?;
        if reopened.epoch_retired
            || metadata(&reopened.connection, &self.request, self.deadline)? != summary
        {
            return Err(failure(
                "published cold epoch differs on independent readback",
            ));
        }
        Ok(Some(summary))
    }
    fn stderr_report(&mut self) -> String {
        #[cfg(target_os = "linux")]
        {
            self.worker.stderr_report()
        }
        #[cfg(any(windows, target_os = "macos"))]
        {
            self.worker
                .failure_diagnostic()
                .unwrap_or_else(|error| format!("stderr unreadable: {error}"))
        }
    }
}
fn metadata(
    db: &CacheConnection<'_>,
    request: &protocol::Request,
    deadline: Instant,
) -> AtlasResult<IndexSummary> {
    db.read(deadline,|sql| {
        let (extractor,ignore,generation,coverage,state):(String,Vec<u8>,i64,String,String)=
            sql.prepare("SELECT extractor_version,ignore_digest,published_generation,coverage_json,state_json FROM meta WHERE singleton=1")?
            .query_row([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(failure)?;
        if extractor!=EXTRACTOR || ignore!=request.ignore_digest.0 {return Err(failure("cold extractor/ignore inputs differ"));}
        Ok(IndexSummary {
            memory: None,project:request.project.clone(),root:request.root.clone(),epoch:Some(request.epoch.clone()),
            generation:Some(Generation(generation.try_into().map_err(failure)?)),
            state:serde_json::from_str(&state).map_err(failure)?,coverage:serde_json::from_str(&coverage).map_err(failure)?})
    })
}
