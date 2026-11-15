//! One parse attempt uses the existing native Atlas process and exact custody.
mod child;
mod collect;
mod protocol;
use crate::atlas_cold::failure;
use se_atlas::{
    errors::AtlasResult, lifecycle::*, model::*, parse::ParserProfile, source::RegisteredSource,
};
use se_proc::atlas_worker::{AtlasWorker, WorkerChannel};
use se_types::{Detail, SeError, code::AtlasText, details};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
type Source = RegisteredSource<crate::atlas_source::NativeAtlasSource>;
pub(crate) use child::run as run_child;

pub(crate) struct Parser {
    profiles: Vec<ParserProfile>,
    image: Option<PathBuf>,
    // A failed reap retains the exact process and global slot for the next close.
    worker: Option<AtlasWorker>,
}
impl Parser {
    pub fn new(profiles: Vec<ParserProfile>) -> Self {
        Self {
            profiles,
            image: None,
            worker: None,
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
            worker.cancel_until(deadline).map_err(failure)?;
        }
        self.worker.take();
        Ok(())
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
        let image = self
            .image
            .as_ref()
            .ok_or_else(|| failure("installed Atlas worker image absent"))?;
        // Keep termination and exact reap inside the original source step.
        let work_end = deadline
            .checked_sub(Duration::from_millis(50))
            .unwrap_or(deadline);
        if work_end <= Instant::now() {
            return Err(expired());
        }
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
            AtlasWorker::spawn(
                image,
                &serde_json::to_vec(&request).map_err(failure)?,
                deadline,
            )
            .map_err(failure)?,
        );
        let worker = self
            .worker
            .as_mut()
            .ok_or_else(|| failure("parse custody absent"))?;
        let result = collect::read(
            worker, source, snapshot, language, budget, profile, work_end,
        );
        if result.is_ok() {
            let completed = (|| {
                worker.observe_memory().map_err(failure)?;
                worker.send_control(b"reap", deadline).map_err(failure)?;
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
            })();
            if let Err(error) = completed {
                if let Err(close) = self.close(deadline) {
                    return Err(close.with_cause(error));
                }
                return Err(error);
            }
        }
        // Neither a reply nor a timeout grants success before exact reap.
        match (self.close(deadline), result) {
            (Ok(()), result) => result,
            (Err(close), Err(error)) => Err(close.with_cause(error)),
            (Err(close), Ok(_)) => Err(close),
        }
    }
}
pub(crate) fn expired() -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas parse attempt".into(),
        deadline_ms: 500,
    }))
}
