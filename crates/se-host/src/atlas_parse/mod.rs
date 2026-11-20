//! One parse attempt uses the existing native Atlas process and exact custody.
mod child;
#[cfg(any(target_os = "linux", windows))]
mod collect;
mod protocol;
use crate::atlas_cold::failure;
use se_atlas::{
    errors::AtlasResult, lifecycle::*, model::*, parse::ParserProfile, source::RegisteredSource,
};
#[cfg(any(target_os = "linux", windows))]
use se_proc::atlas_worker::AtlasWorker;
use se_proc::atlas_worker::WorkerChannel;
use se_types::{Detail, SeError, details};
use std::time::Duration;
#[cfg(any(target_os = "linux", windows))]
use std::{
    path::{Path, PathBuf},
    time::Instant,
};
type Source = RegisteredSource<crate::atlas_source::NativeAtlasSource>;
pub(crate) use child::run as run_child;

#[cfg(any(target_os = "linux", windows))]
pub(crate) struct Parser {
    profiles: Vec<ParserProfile>,
    image: Option<PathBuf>,
    // A failed reap retains the exact process and global slot for the next close.
    worker: Option<AtlasWorker>,
    attempt: Option<Attempt>,
}
#[cfg(any(target_os = "linux", windows))]
struct Attempt {
    file: se_types::code::FileId,
    identity: FileIdentity,
    hash: se_types::code::ContentHash,
    language: Language,
    budget: ParseBudget,
    spent: Duration,
    wall: Duration,
}
#[cfg(any(target_os = "linux", windows))]
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
        // A resident worker survives between files; probe once so a dead
        // worker releases its slot before the next request reuses or spawns.
        let worker_died = self
            .worker
            .as_mut()
            .is_some_and(|worker| worker.try_reap().is_ok_and(|status| status.is_some()));
        if worker_died {
            self.worker = None;
        }
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
            .clone()
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
        let request_bytes = serde_json::to_vec(&request).map_err(failure)?;
        // Custody is decided inside run_file: on return, the worker is
        // either retained or already closed and the slot released.
        let (result, consumed) = self.run_file(
            &image,
            &request_bytes,
            collect::Context {
                source,
                snapshot,
                language,
                budget,
                profile,
                deadline: work_end,
            },
            deadline,
            work_end,
            budget.max_work.saturating_sub(spent),
        )?;
        // Neither a reply nor a timeout grants success before exact reap.
        let timed_out = matches!(&result, Err(error) if matches!(error.body.detail(),
            Detail::DeadlineExceeded(detail) if detail.op == "Atlas parse attempt" || detail.op == "Atlas parse CPU"));
        let stalled = if timed_out {
            self.charge_attempt(consumed, started.elapsed())
        } else {
            Ok(false)
        };
        match stalled {
            Ok(stalled) => {
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
            Err(accounting) => Err(accounting),
        }
    }
    /// Reuse the resident worker or spawn it, read the bounded file result,
    /// and leave custody consistent on every outcome: the single retain
    /// decision below keeps the worker only for a complete file, otherwise
    /// the exact child is closed and its slot released.
    fn run_file(
        &mut self,
        image: &Path,
        request_bytes: &[u8],
        context: collect::Context<'_>,
        deadline: Instant,
        work_end: Instant,
        remaining: Duration,
    ) -> AtlasResult<(AtlasResult<ParsedFile>, Duration)> {
        // Deliver the request. A failed send closes the exact child first,
        // so no early return leaves a live process or a held slot behind;
        // a failed spawn reaps its own child and holds no slot.
        if self.worker.is_some() {
            let error = self
                .worker
                .as_mut()
                .and_then(|worker| {
                    worker.extend_deadline(deadline);
                    worker.send_control(request_bytes, work_end).err()
                })
                .map(|error| collect::channel_error(error, work_end));
            if let Some(error) = error {
                return Err(self.closed_error(deadline, error));
            }
        } else {
            self.worker = Some(
                AtlasWorker::spawn_bounded(image, request_bytes, deadline)
                    .map_err(|error| start_error(error, deadline))?,
            );
        }
        let worker = match self.worker.as_mut() {
            Some(worker) => worker,
            // Neither branch left a child, so there is no custody to
            // release; this is a plain invariant failure.
            None => return Err(failure("parse custody absent")),
        };
        let mut consumed = Duration::ZERO;
        let result = collect::read(worker, context, remaining, &mut consumed);
        // One decision per outcome: only a complete file keeps its worker.
        // A failed or desynchronized read leaves the child mid-custody, and
        // a deferred ParseMemoryLimit file has driven the child to its
        // memory peak, so the next file gets a fresh guard window. A failed
        // peak observation fails the file, as a failed close did.
        let (retain, custody) = match &result {
            Ok(parsed)
                if matches!(
                    parsed.coverage,
                    FileCoverage::Deferred {
                        reason: CoverageReason::ParseMemoryLimit
                    }
                ) =>
            {
                (false, Ok(()))
            }
            Ok(_) => {
                let guard = worker.observe_memory().map(|_| ()).map_err(failure);
                (guard.is_ok(), guard)
            }
            Err(_) => (false, Ok(())),
        };
        if retain {
            return Ok((result, consumed));
        }
        let close = self.close(deadline);
        match (close, custody.and(result)) {
            (Ok(()), result) => Ok((result, consumed)),
            (Err(close), Err(error)) => Err(close.with_cause(error)),
            (Err(close), Ok(_)) => Err(close),
        }
    }
    /// Close the exact child; a failed close carries the delivery error as
    /// its cause so both custody failures stay diagnosable.
    fn closed_error(&mut self, deadline: Instant, error: SeError) -> SeError {
        match self.close(deadline) {
            Ok(()) => error,
            Err(close) => close.with_cause(error),
        }
    }
}
#[cfg(any(target_os = "linux", windows))]
fn start_error(error: std::io::Error, deadline: Instant) -> SeError {
    cleanup_error(error, deadline.saturating_duration_since(Instant::now()))
}
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn expired() -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas parse attempt".into(),
        deadline_ms: 500,
    }))
}
pub(crate) use se_atlas_cold::deadline::{cleanup_error, cpu_expired, stall};

#[cfg(any(target_os = "linux", windows))]
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
