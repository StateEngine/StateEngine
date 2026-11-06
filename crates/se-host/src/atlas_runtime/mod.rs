//! Native host composition. Renewal borrows this owner's one SQL connection.
use crate::atlas_source::NativeAtlasSource;
use crate::{atlas_cache::NativeAtlasCache, atlas_cold};
use se_atlas::{
    cache::connection::CacheConnection, controller::Step, errors::AtlasResult, model::AtlasPolicy,
    scheduler::Scheduled, source::RegisteredSource,
};
use se_atlas::{
    cache::{connection::*, *},
    controller::{Controller, Runtime},
    lifecycle::*,
    model::*,
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
mod close;
mod connections;
#[cfg(all(feature = "runtime", target_os = "linux"))]
pub(crate) mod project_work;
pub mod read_port;
pub mod record_fence;
mod runtime;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use crate::atlas_cold::protocol;
pub type NativeController<D> = Controller<NativeRuntime<D>>;
struct Root {
    source: RegisteredSource<NativeAtlasSource>,
    policy: AtlasPolicy,
    summary: IndexSummary,
    waiting_on_child: bool,
    needs_rebuild: bool,
    serial_domain: Option<(CacheEpoch, u64)>,
    checked_epoch: Option<CacheEpoch>,
}
pub struct NativeRuntime<D> {
    home: PathBuf,
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    image: PathBuf,
    roots: Vec<Root>,
    driver: D,
    profile: Option<SqlProfile>,
    pending: Option<WorkerRequest>,
    active: Option<(AtlasJobId, RootId)>,
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    child: Option<atlas_cold::job::ColdJob>,
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    child_failure: Option<se_types::ErrorBody>,
}
impl<D: RenewalDriver> NativeRuntime<D> {
    /// No IO or activation here. Supply a native-qualified SQL profile before
    /// using steady host readers/writers; None permits the isolated cold path.
    pub fn new(
        home: PathBuf,
        image: PathBuf,
        driver: D,
        profile: Option<SqlProfile>,
    ) -> AtlasResult<Self> {
        if !home.is_absolute() || !image.is_absolute() {
            return Err(atlas_cold::failure(
                "absolute owned home and installed image required",
            ));
        }
        Ok(Self {
            home,
            #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
            image,
            roots: Vec::new(),
            driver,
            profile,
            pending: None,
            active: None,
            #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
            child: None,
            #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
            child_failure: None,
        })
    }
    fn root(&self, id: &RootId) -> AtlasResult<&Root> {
        self.roots
            .iter()
            .find(|r| &r.summary.root == id)
            .ok_or_else(|| atlas_cold::failure("native root is not activated"))
    }
    fn admit(&mut self, registration: &RootRegistration, policy: &AtlasPolicy) -> AtlasResult<()> {
        if self
            .roots
            .iter()
            .any(|r| r.summary.root == registration.root)
        {
            return Ok(());
        }
        if self.roots.len() >= 2 {
            return Err(atlas_cold::failure(
                "native live resource slots are occupied; recycle an idle slot",
            ));
        }
        if registration.cache.directory
            != self
                .home
                .join(registration.project.as_str())
                .join(registration.root.as_str())
        {
            return Err(atlas_cold::failure(
                "registered cache differs from fixed owned-home path",
            ));
        }
        let source = NativeAtlasSource::open(
            registration.clone(),
            if cfg!(windows) {
                CaseMode::InsensitivePreserving
            } else {
                CaseMode::Sensitive
            },
        )?;
        let cache = NativeAtlasCache::open(&self.home, source.scope.clone())?;
        let bytes = cache
            .as_ref()
            .map(|c| c.read_pointer())
            .transpose()?
            .flatten();
        let pointer = bytes
            .as_ref()
            .map(|b| pointer::decode(b, &source.scope))
            .transpose()?;
        let needs_rebuild = pointer
            .as_ref()
            .is_some_and(|p| p.schema < se_atlas::cache::schema::SCHEMA_VERSION);
        let epoch = pointer.map(|p| p.epoch);
        let summary = IndexSummary {
            memory: None,
            project: registration.project.clone(),
            root: registration.root.clone(),
            epoch,
            generation: None,
            state: IndexState::VerificationNeeded {
                reason: CoverageReason::StaleSnapshot,
            },
            coverage: atlas_cold::empty_coverage(),
        };
        self.roots.push(Root {
            source,
            policy: policy.clone(),
            summary,
            waiting_on_child: false,
            needs_rebuild,
            serial_domain: None,
            checked_epoch: None,
        });
        Ok(())
    }
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }
    pub fn summary(&self, id: &RootId) -> AtlasResult<IndexSummary> {
        Ok(self.root(id)?.summary.clone())
    }
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    pub fn child_pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.pid())
    }
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    pub fn wait_child_ready(&mut self, deadline: Instant) -> AtlasResult<bool> {
        self.child
            .as_mut()
            .map(|c| c.wait_ready(deadline))
            .transpose()
            .map(|v| v.unwrap_or(false))
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn child_readiness_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.child.as_ref().map(|c| c.readiness_fd())
    }
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    pub fn dispatch_child(&mut self) -> AtlasResult<Option<WorkerEvent>> {
        if self.child.is_some() {
            return Ok(None);
        }
        let Some(request) = self.pending.take() else {
            return Ok(None);
        };
        let job = request.job;
        let spawned: AtlasResult<_> = (|| {
            let root = self.root(&request.root.root)?;
            let mut entropy = [0; 10];
            se_proc::fill_entropy(&mut entropy).map_err(atlas_cold::failure)?;
            let millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(atlas_cold::failure)?
                .as_millis();
            let epoch =
                CacheEpoch::from_parts(millis.try_into().map_err(atlas_cold::failure)?, entropy)?;
            let frame = protocol::Request {
                history_unavailable: None,
                job: request.job,
                project: request.root.project,
                root: request.root.root,
                source_root: se_types::NativePath::from_local(request.root.canonical_source_root)?,
                home: se_types::NativePath::from_local(self.home.clone())?,
                physical_root: root.source.scope.physical_root,
                expected_epoch: request.expected_epoch,
                epoch,
                max_files: request.policy.max_files,
                ignore_digest: request.policy.ignore.digest,
                global_patterns: request.policy.ignore.global_patterns,
                generated_prefixes: request.policy.ignore.generated_prefixes,
            };
            let child = if let Some(metadata) = request.root.git_metadata {
                atlas_cold::job::ColdJob::spawn_with_history(
                    &self.image,
                    frame,
                    metadata,
                    self.profile.as_ref(),
                )?
            } else {
                atlas_cold::job::ColdJob::spawn(&self.image, frame)?
            };
            Ok(child)
        })();
        let child = match spawned {
            Ok(child) => child,
            Err(error) => {
                return Ok(Some(WorkerEvent::Exited {
                    job,
                    outcome: WorkerExit::Failed { error: error.body },
                }));
            }
        };
        self.child = Some(child);
        Ok(Some(WorkerEvent::Started { job }))
    }
    /// Host calls on native socket/child readiness or its finite job deadline.
    /// No thread, idle polling timer or provider capability is introduced.
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    pub fn poll_child(&mut self) -> AtlasResult<Option<WorkerEvent>> {
        let Some(child) = &mut self.child else {
            return Ok(None);
        };
        let job = child.request.job;
        let result = match &self.child_failure {
            Some(error) => Err(se_types::SeError::from(error.clone())),
            None => child.poll(),
        };
        match result {
            Ok(None) => {
                if let Some(root) = self
                    .roots
                    .iter_mut()
                    .find(|root| root.summary.root == child.request.root)
                {
                    root.summary.state = IndexState::ColdIndexing {
                        job,
                        discovered_files: child.discovered_files(),
                    };
                }
                Ok(None)
            }
            Ok(Some(summary)) => {
                let root = self
                    .roots
                    .iter_mut()
                    .find(|r| r.summary.root == summary.root)
                    .ok_or_else(|| atlas_cold::failure("completed native root disappeared"))?;
                root.summary = summary;
                root.needs_rebuild = false;
                root.serial_domain = None;
                let epoch = root
                    .summary
                    .epoch
                    .clone()
                    .ok_or_else(|| atlas_cold::failure("completed native epoch absent"))?;
                // ColdJob independently reopens, integrity-checks and reads
                // back the exact candidate after reaping its child.
                root.checked_epoch = Some(epoch.clone());
                self.child.take();
                Ok(Some(WorkerEvent::Exited {
                    job,
                    outcome: WorkerExit::Completed {
                        staged_cache: root.source.scope.registration.cache.clone(),
                        candidate_epoch: epoch,
                    },
                }))
            }
            Err(error) => {
                self.child_failure = Some(error.body.clone());
                if let Err(cancel) = child.cancel() {
                    // Keep exact child custody and the original protocol/native
                    // failure; cleanup latency must not erase the crash cause.
                    return Err(cancel.with_cause(error));
                }
                self.child.take();
                self.child_failure = None;
                Ok(Some(WorkerEvent::Exited {
                    job,
                    outcome: WorkerExit::Failed { error: error.body },
                }))
            }
        }
    }
}

/// Host composition uses this on after-ready work and native child readiness.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub fn drive_child<D: RenewalDriver>(controller: &mut NativeController<D>) -> AtlasResult<bool> {
    let mut acted = false;
    if let Some(event) = controller.runtime_mut().dispatch_child()? {
        controller.child_event(event)?;
        acted = true;
    }
    if let Some(event) = controller.runtime_mut().poll_child()? {
        let exited = matches!(event, WorkerEvent::Exited { .. });
        controller.child_event(event)?;
        if exited {
            let waiters: Vec<_> = controller
                .runtime_mut()
                .roots
                .iter_mut()
                .filter_map(|r| {
                    if std::mem::take(&mut r.waiting_on_child) {
                        Some(r.summary.root.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for root in waiters {
                controller.enqueue(root, SourceHint::Reconcile(ReconcileReason::HostRestart))?;
            }
        }
        acted = true;
    }
    Ok(acted)
}

pub trait RenewalDriver {
    fn step(
        &mut self,
        source: &RegisteredSource<NativeAtlasSource>,
        connection: &CacheConnection<'_>,
        policy: &AtlasPolicy,
        work: &Scheduled,
        deadline: Instant,
    ) -> AtlasResult<Step>;
    fn poll_events(
        &mut self,
        source: &RegisteredSource<NativeAtlasSource>,
        connection: &CacheConnection<'_>,
        policy: &AtlasPolicy,
        deadline: Instant,
    ) -> AtlasResult<Vec<SourceHint>>;
    /// Idempotently release native custody even without a cache connection.
    /// A supplied connection may also persist derived watch metadata; neither
    /// form may start native work. Actual custody failures must be returned.
    fn close(
        &mut self,
        root: &RootId,
        connection: Option<&CacheConnection<'_>>,
        deadline: Instant,
    ) -> AtlasResult<()>;
    #[cfg(unix)]
    fn event_fd(&self, _root: &RootId) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }
}
