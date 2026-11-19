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
    parse_deadline: Option<Instant>,
    parse_stall_deadline: Option<Instant>,
    parse_cpu_start: Option<Duration>,
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
        let worker = se_proc::atlas_worker::AtlasWorker::spawn_bounded(
            image,
            &serde_json::to_vec(&request).map_err(failure)?,
            deadline,
        )
        .map_err(|error| {
            crate::atlas_parse::cleanup_error(
                error,
                deadline.saturating_duration_since(Instant::now()),
            )
        })?;
        Ok(Self {
            worker,
            request,
            expected,
            history,
            deadline,
            parse_deadline: None,
            parse_stall_deadline: None,
            parse_cpu_start: None,
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
    pub(crate) fn discovered_files(&self) -> u64 {
        self.discovered
    }
    pub fn parse_deadline(&self) -> Option<Instant> {
        self.parse_deadline
    }
    pub fn next_deadline(&self) -> Instant {
        self.parse_deadline
            .unwrap_or(self.deadline)
            .min(self.deadline)
    }
    pub fn cancellation_deadline(&self) -> Instant {
        self.parse_stall_deadline.map_or(self.deadline, |end| {
            (end + Duration::from_millis(300)).min(self.deadline)
        })
    }
    pub fn wait_ready(&mut self, deadline: Instant) -> AtlasResult<bool> {
        self.worker
            .wait_ready(deadline.min(self.next_deadline()))
            .map_err(|error| self.native_io_failure(error))
    }
    #[cfg(unix)]
    pub fn readiness_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.worker.readiness_fd()
    }
    pub fn cancel(&mut self) -> AtlasResult<()> {
        self.cancel_until(
            (Instant::now() + Duration::from_millis(200)).min(self.cancellation_deadline()),
        )
    }
    /// Shutdown lends its remaining host budget to exact native cancellation.
    pub fn cancel_until(&mut self, deadline: Instant) -> AtlasResult<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        self.worker
            .cancel_until(deadline)
            .map_err(|error| crate::atlas_parse::cleanup_error(error, remaining))
    }
    fn reject(&mut self, reason: &'static str) -> SeError {
        let rejected = failure(reason);
        match self.cancel() {
            Ok(()) => rejected,
            Err(cancel) => rejected.with_cause(cancel),
        }
    }
    fn native_io_failure(&mut self, error: std::io::Error) -> SeError {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            crate::atlas_parse::cleanup_error(
                error,
                self.deadline.saturating_duration_since(Instant::now()),
            )
        } else {
            self.native_failure(error)
        }
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
    fn check_file_work(&mut self) -> AtlasResult<()> {
        let Some(start) = self.parse_cpu_start else {
            return Ok(());
        };
        let end = self
            .parse_stall_deadline
            .ok_or_else(|| failure("cold file stall deadline absent"))?;
        let current = match self.worker.cpu_time() {
            Ok(current) => current,
            Err(error) => {
                if let Some(status) = self.worker.try_reap().map_err(failure)? {
                    return Err(self.native_failure(format!("cold child exited {status}")));
                }
                return Err(failure(error));
            }
        };
        let cpu = current
            .checked_sub(start)
            .ok_or_else(|| failure("cold worker CPU clock moved backwards"))?;
        let error = if cpu >= Duration::from_millis(250) {
            Some(crate::atlas_parse::cpu_expired(Duration::from_millis(200)))
        } else if Instant::now() >= self.deadline {
            Some(crate::atlas_parse::stall(Duration::from_secs(900)))
        } else if Instant::now() >= end {
            Some(crate::atlas_parse::stall(Duration::from_secs(5)))
        } else {
            None
        };
        if let Some(error) = error {
            if let Err(cancel) = self.cancel_until(self.cancellation_deadline()) {
                return Err(cancel.with_cause(error));
            }
            return Err(error);
        }
        self.parse_deadline = Some((Instant::now() + Duration::from_millis(10)).min(end));
        Ok(())
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn poll(&mut self) -> AtlasResult<Option<IndexSummary>> {
        while let Some(bytes) = self
            .worker
            .receive()
            .map_err(|error| self.native_io_failure(error))?
        {
            let reply: protocol::Reply = serde_json::from_slice(&bytes).map_err(failure)?;
            match reply {
                protocol::Reply::Diagnostic {
                    job,
                    files,
                    frames,
                    commit_us,
                    success,
                } => {
                    if job != self.request.job {
                        return Err(self.reject("foreign cold diagnostic"));
                    }
                    eprintln!(
                        "ATLAS_BATCH_FRAMES files={files} frames={frames} commit_us={commit_us} success={success}"
                    );
                }
                protocol::Reply::Working { job, path, phase } => {
                    if job != self.request.job {
                        return Err(self.reject("foreign cold phase report"));
                    }
                    if let Some(path) = path {
                        self.last_path = Some(path);
                    }
                    if matches!(phase, protocol::Phase::SourceRead) {
                        if self.parse_cpu_start.is_some() {
                            return Err(failure("duplicate source read phase"));
                        }
                        // The worker is waiting; setup CPU is outside the file budget.
                        self.parse_cpu_start = Some(self.worker.cpu_time().map_err(failure)?);
                        let end = (Instant::now() + Duration::from_secs(5)).min(self.deadline);
                        self.parse_stall_deadline = Some(end);
                        self.parse_deadline =
                            Some((Instant::now() + Duration::from_millis(10)).min(end));
                        self.worker.send_control(b"source", end).map_err(|error| {
                            crate::atlas_parse::cleanup_error(
                                error,
                                end.saturating_duration_since(Instant::now()),
                            )
                        })?;
                    } else if matches!(phase, protocol::Phase::Parse) {
                        if self.parse_cpu_start.is_none() {
                            return Err(failure("parse phase without source read authorization"));
                        }
                    } else {
                        self.parse_deadline = None;
                        self.parse_stall_deadline = None;
                        self.parse_cpu_start = None;
                        if matches!(phase, protocol::Phase::Resolve | protocol::Phase::Commit) {
                            self.worker.send_control(b"source", self.deadline).map_err(
                                |error| {
                                    crate::atlas_parse::cleanup_error(
                                        error,
                                        self.deadline.saturating_duration_since(Instant::now()),
                                    )
                                },
                            )?;
                        }
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
                        return Err(
                            self.reject("cold progress does not match the one-use job/bounds")
                        );
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
                        return Err(self.reject("cold completion does not match job/root/epoch or explicit partial discovery"));
                    }
                    self.completion = Some(*summary);
                    self.worker.acknowledge_completion().map_err(|error| {
                        crate::atlas_parse::cleanup_error(error, Duration::from_millis(200))
                    })?;
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
                    if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(detail) if detail.op == "Atlas scheduling stall")
                    {
                        return Err(error);
                    }
                    return Err(self.native_failure(&error).with_cause(error));
                }
            }
        }
        self.check_file_work()?;
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
        let mut candidate = CacheConnection::open(
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
        let actual = metadata(&mut candidate, &self.request, self.deadline)?;
        if actual != summary {
            return Err(failure(
                "child summary differs from independently reopened candidate",
            ));
        }
        let mut candidate = if let Some(history) = self.history.take() {
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
            let mut candidate = CacheConnection::open(
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
            if metadata(&mut candidate, &self.request, self.deadline)? != summary {
                return Err(failure("history candidate differs before publication"));
            }
            candidate
        } else {
            candidate
        };
        pointer::publish(
            &cache,
            &mut candidate,
            self.expected.as_deref(),
            self.deadline,
        )?;
        drop(candidate);
        drop(cache);
        let readback = NativeAtlasCache::open(&self.request.home.to_local()?, scope.clone())?
            .ok_or_else(|| failure("published cache missing on readback"))?;
        let mut reopened = pointer::open_current(
            &readback,
            &scope,
            ConnectionRole::ExternalReader,
            &profile,
            self.deadline,
        )?
        .ok_or_else(|| failure("published epoch missing on independent readback"))?;
        if reopened.epoch_retired
            || metadata(&mut reopened.connection, &self.request, self.deadline)? != summary
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
    db: &mut CacheConnection<'_>,
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
