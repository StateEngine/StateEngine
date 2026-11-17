//! One parse attempt uses the existing native Atlas process and exact custody.
mod child;
#[cfg(target_os = "linux")]
mod collect;
mod protocol;
use crate::atlas_cold::failure;
use se_atlas::{
    errors::AtlasResult, lifecycle::*, model::*, parse::ParserProfile, source::RegisteredSource,
};
#[cfg(target_os = "linux")]
use se_proc::atlas_worker::AtlasWorker;
use se_proc::atlas_worker::WorkerChannel;
use se_types::{Detail, SeError, details};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{
    path::{Path, PathBuf},
    time::Instant,
};
type Source = RegisteredSource<crate::atlas_source::NativeAtlasSource>;
pub(crate) use child::run as run_child;

#[cfg(target_os = "linux")]
pub(crate) struct Parser {
    profiles: Vec<ParserProfile>,
    image: Option<PathBuf>,
    // A failed reap retains the exact process and global slot for the next close.
    worker: Option<AtlasWorker>,
    attempt: Option<Attempt>,
}
#[cfg(target_os = "linux")]
struct Attempt {
    file: se_types::code::FileId,
    identity: FileIdentity,
    hash: se_types::code::ContentHash,
    language: Language,
    budget: ParseBudget,
    spent: Duration,
    wall: Duration,
}
#[cfg(target_os = "linux")]
impl Parser {
    pub fn new(profiles: Vec<ParserProfile>) -> Self {
        Self {
            profiles,
            image: None,
            worker: None,
            attempt: None,
        }
    }
    pub fn bind_image(&mut self, image: &Path) {
        self.image = Some(image.to_path_buf());
    }
    pub fn profile(&self, language: Language) -> Option<ParserProfile> {
        self.profiles
            .iter()
            .find(|p| p.language == language)
            .copied()
    }
    pub fn close(&mut self, deadline: Instant) -> AtlasResult<()> {
        if let Some(worker) = &mut self.worker {
            let remaining = deadline.saturating_duration_since(Instant::now());
            worker
                .cancel_until(deadline)
                .map_err(|error| cleanup_error(error, remaining))?;
        }
        self.worker.take();
        Ok(())
    }
    fn attempt_spent(
        &mut self,
        source: &Source,
        snapshot: &SourceSnapshot,
        language: Language,
        budget: ParseBudget,
    ) -> AtlasResult<Duration> {
        let file = source.scope.file_id(&snapshot.path);
        if !self.attempt.as_ref().is_some_and(|attempt| {
            attempt.file == file
                && attempt.identity == snapshot.identity
                && attempt.hash == snapshot.content_hash
                && attempt.language == language
                && attempt.budget == budget
        }) {
            self.attempt = Some(Attempt {
                file,
                identity: snapshot.identity.clone(),
                hash: snapshot.content_hash,
                language,
                budget,
                spent: Duration::ZERO,
                wall: Duration::ZERO,
            });
        }
        self.attempt
            .as_ref()
            .map(|attempt| attempt.spent)
            .ok_or_else(|| failure("parse attempt accounting absent"))
    }
    fn charge_attempt(&mut self, consumed: Duration, elapsed: Duration) -> AtlasResult<bool> {
        let attempt = self
            .attempt
            .as_mut()
            .ok_or_else(|| failure("parse attempt accounting absent"))?;
        attempt.spent = attempt.spent.saturating_add(consumed);
        attempt.wall = attempt.wall.saturating_add(elapsed);
        if attempt.wall >= Duration::from_secs(5) {
            attempt.wall = Duration::ZERO;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn may_retry(&self, budget: ParseBudget) -> AtlasResult<bool> {
        Ok(self
            .attempt
            .as_ref()
            .ok_or_else(|| failure("parse attempt accounting absent"))?
            .spent
            < budget.max_work)
    }
    pub fn parse(
        &mut self,
        source: &Source,
        snapshot: &SourceSnapshot,
        language: Language,
        budget: ParseBudget,
        deadline: Instant,
    ) -> AtlasResult<ParsedFile> {
        self.close(deadline)?;
        let profile = self
            .profile(language)
            .ok_or_else(|| failure("qualified parse profile absent"))?;
        // Keep termination and exact reap inside the original source step.
        let spent = self.attempt_spent(source, snapshot, language, budget)?;
        if spent >= budget.max_work {
            let result = outcome(Err(expired()), source, snapshot, language, deadline, false);
            if result.is_ok() {
                self.attempt = None;
            }
            return result;
        }
        let started = Instant::now();
        let work_end = deadline
            .checked_sub(Duration::from_millis(50))
            .unwrap_or(deadline);
        if work_end <= Instant::now() {
            return Err(expired());
        }
        let image = self
            .image
            .as_ref()
            .ok_or_else(|| failure("installed Atlas worker image absent"))?;
        let request = protocol::Request {
            parse_only: true,
            project: source.scope.registration.project.clone(),
            root: source.scope.registration.root.clone(),
            source_root: se_types::NativePath::from_local(
                source.scope.registration.canonical_source_root.clone(),
            )?,
            cache_directory: se_types::NativePath::from_local(
                source.scope.registration.cache.directory.clone(),
            )?,
            physical_root: source.scope.physical_root,
            path: snapshot.path.clone(),
            identity: snapshot.identity.clone(),
            content_hash: snapshot.content_hash,
            language,
            budget,
            profile,
        };
        self.worker = Some(
            AtlasWorker::spawn_bounded(
                image,
                &serde_json::to_vec(&request).map_err(failure)?,
                deadline,
            )
            .map_err(|error| start_error(error, deadline))?,
        );
        let worker = self
            .worker
            .as_mut()
            .ok_or_else(|| failure("parse custody absent"))?;
        let mut consumed = Duration::ZERO;
        let result = collect::read(
            worker,
            collect::Context {
                source,
                snapshot,
                language,
                budget,
                profile,
                deadline: work_end,
            },
            budget.max_work.saturating_sub(spent),
            &mut consumed,
        );
        let result = if result.is_ok() {
            finish_worker(worker, deadline).and(result)
        } else {
            result
        };
        // Neither a reply nor a timeout grants success before exact reap.
        let timed_out = matches!(&result, Err(error) if matches!(error.body.detail(),
            Detail::DeadlineExceeded(detail) if detail.op == "Atlas parse attempt" || detail.op == "Atlas parse CPU"));
        let stalled = if timed_out {
            self.charge_attempt(consumed, started.elapsed())
        } else {
            Ok(false)
        };
        match (self.close(deadline), result, stalled) {
            (Ok(()), result, Ok(stalled)) => {
                let retry_slice = if timed_out {
                    self.may_retry(budget)?
                } else {
                    false
                };
                let result = if stalled && retry_slice {
                    Err(stall(Duration::from_secs(5)))
                } else {
                    outcome(result, source, snapshot, language, deadline, retry_slice)
                };
                if result.is_ok() || !timed_out {
                    self.attempt = None;
                }
                result
            }
            (Ok(()), _, Err(accounting)) => Err(accounting),
            (Err(close), Err(error), _) => Err(close.with_cause(error)),
            (Err(close), Ok(_), _) => Err(close),
        }
    }
}
#[cfg(target_os = "linux")]
fn finish_worker(worker: &mut AtlasWorker, deadline: Instant) -> AtlasResult<()> {
    worker.observe_memory().map_err(failure)?;
    worker
        .send_control(b"reap", deadline)
        .map_err(|error| collect::channel_error(error, deadline))?;
    loop {
        if let Some(status) = worker.try_reap().map_err(failure)? {
            if !status.success() {
                return Err(failure("parse child exited unsuccessfully"));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(expired());
        }
        worker.wait_ready(deadline).map_err(failure)?;
    }
}
#[cfg(target_os = "linux")]
fn start_error(error: std::io::Error, deadline: Instant) -> SeError {
    cleanup_error(error, deadline.saturating_duration_since(Instant::now()))
}
#[cfg(target_os = "linux")]
pub(crate) fn expired() -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas parse attempt".into(),
        deadline_ms: 500,
    }))
}
pub(crate) fn cpu_expired(limit: Duration) -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas parse CPU".into(),
        deadline_ms: limit.as_millis().min(u128::from(u64::MAX)) as u64,
    }))
}
pub(crate) fn cleanup_error(error: std::io::Error, limit: Duration) -> SeError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        stall(limit).with_cause(error)
    } else {
        failure(error)
    }
}
pub(crate) fn stall(limit: Duration) -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas scheduling stall".into(),
        deadline_ms: limit.as_millis().min(u128::from(u64::MAX)) as u64,
    }))
}

#[cfg(target_os = "linux")]
// A completed cancellation is a finite file refusal, not an endless retry of
// the same unparseable revision. No late child row survives into this result.
fn outcome(
    result: AtlasResult<ParsedFile>,
    source: &Source,
    snapshot: &SourceSnapshot,
    language: Language,
    deadline: Instant,
    retry_slice: bool,
) -> AtlasResult<ParsedFile> {
    match result {
        Err(error)
            if !retry_slice
                && Instant::now() >= deadline
                && matches!(error.body.detail(), Detail::DeadlineExceeded(detail)
                    if detail.op == "Atlas parse CPU") =>
        {
            Err(expired())
        }
        Err(error)
            if !retry_slice
                && Instant::now() < deadline
                && matches!(error.body.detail(),
            Detail::DeadlineExceeded(detail) if detail.op == "Atlas parse attempt" || detail.op == "Atlas parse CPU") =>
        {
            Ok(ParsedFile {
                file: source.scope.file_id(&snapshot.path),
                language,
                content_hash: snapshot.content_hash,
                coverage: FileCoverage::Deferred {
                    reason: CoverageReason::ParseWorkLimit,
                },
                symbols: Vec::new(),
                imports: Vec::new(),
                references: Vec::new(),
                scopes: Vec::new(),
            })
        }
        result => result,
    }
}
