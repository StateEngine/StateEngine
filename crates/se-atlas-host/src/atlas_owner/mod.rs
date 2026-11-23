//! The host's Atlas owner: one v5 engine per registered worktree, started
//! after readiness. Registration comes from the authoritative catalogue and
//! from queries; the owner loop feeds committed records into each engine.
//! No SQL handle crosses an await, and all disk work runs off the runtime.
mod qualification;
mod read;
mod records;
mod roots;
use crate::host::AtlasHost;
use se_atlas::{cache::connection::SqlProfile, parse::ParserProfile};
use se_atlas_service::{Root, RootSpec};
use se_core::store_error::store_error;
use se_store::{Actor, Admission, Scope, Snapshot};
use se_types::{HumanId, ProjectId, Result, SeError, code::RootId};
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::{
    any::Any,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// Retained for installers that still pass legacy native measurements. The
/// v5 engine runs no native parser and needs no admission profile.
#[derive(Default, Debug)]
pub struct NativeAtlasQualification {
    pub sql: Option<SqlProfile>,
    pub parsers: Vec<ParserProfile>,
}

pub struct Service {
    home: PathBuf,
    owner: HumanId,
    enabled: bool,
    interests: Arc<crate::atlas_runtime::record_fence::RecordFeedFence>,
    roots: Mutex<Vec<Registered>>,
    /// Projects whose committed records may not all be in their engines.
    feeding: Mutex<Vec<ProjectId>>,
}

/// One registered worktree; `root` is absent while Atlas is disabled.
struct Registered {
    spec: RootSpec,
    root: Option<Arc<Root>>,
}

/// Bound for stopping one replaced worktree's writer.
const REPLACE_STOP: Duration = Duration::from_secs(2);
/// Pause before the next pass while record feed is still waiting.
const FEED_AGAIN: Duration = Duration::from_millis(50);
/// Pause before retrying a feed write that failed or timed out.
const FEED_BACKOFF: Duration = Duration::from_millis(500);
/// Time one pass spends feeding before it yields.
const FEED_PASS: Duration = Duration::from_millis(250);

impl Service {
    pub fn new(
        state_directory: &std::path::Path,
        _image: PathBuf,
        owner: HumanId,
        enabled: bool,
        _qualification: NativeAtlasQualification,
        interests: Arc<crate::atlas_runtime::record_fence::RecordFeedFence>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            home: state_directory.join("atlas-v5"),
            owner,
            enabled,
            interests,
            roots: Mutex::new(Vec::new()),
            feeding: Mutex::new(Vec::new()),
        }))
    }

    fn roots(&self) -> Result<MutexGuard<'_, Vec<Registered>>> {
        self.roots.lock().map_err(|_| busy())
    }

    /// Make `specs` the project's worktrees, starting new engines and
    /// stopping ones whose worktree left or moved. True when anything changed.
    fn register(&self, project: &ProjectId, specs: Vec<RootSpec>) -> Result<bool> {
        let mut retired = Vec::new();
        let mut failed = None;
        let changed = {
            let mut roots = self.roots()?;
            let before = roots.len();
            let mut changed = false;
            roots.retain_mut(|registered| {
                let keep = &registered.spec.project != project
                    || specs.iter().any(|spec| spec == &registered.spec);
                if !keep {
                    changed = true;
                    retired.extend(registered.root.take());
                }
                keep
            });
            for spec in specs {
                if roots.iter().any(|registered| registered.spec == spec) {
                    continue;
                }
                let root = if self.enabled {
                    match Root::start(spec.clone()) {
                        Ok(root) => Some(root),
                        Err(error) => {
                            // Retired writers still stop below.
                            failed.get_or_insert(error);
                            continue;
                        }
                    }
                } else {
                    None
                };
                roots.push(Registered { spec, root });
                changed = true;
            }
            changed || roots.len() != before
        };
        for root in retired {
            if let Err(error) = root.stop(REPLACE_STOP) {
                eprintln!("Code index writer for a removed worktree did not stop: {error}");
            }
        }
        if changed && self.enabled {
            self.need_feed([project.clone()])?;
        }
        match failed {
            Some(error) => Err(error),
            None => Ok(changed),
        }
    }

    /// The project's selected worktree.
    fn select(
        &self,
        project: &ProjectId,
        selected: Option<&RootId>,
    ) -> Result<(RootSpec, Option<Arc<Root>>)> {
        let roots = self.roots()?;
        let mut matching = roots.iter().filter(|registered| {
            &registered.spec.project == project
                && selected.is_none_or(|id| id == &registered.spec.root)
        });
        let first = matching.next().ok_or_else(|| {
            SeError::invalid(
                "Atlas query root",
                "a current registered worktree of this project",
            )
        })?;
        if matching.next().is_some() {
            return Err(SeError::invalid(
                "Atlas query root",
                "an explicit root when the project has several worktrees",
            ));
        }
        Ok((first.spec.clone(), first.root.clone()))
    }

    fn started(&self) -> Result<Vec<Arc<Root>>> {
        Ok(self
            .roots()?
            .iter()
            .filter_map(|registered| registered.root.clone())
            .collect())
    }
}

fn busy() -> SeError {
    se_core::scope::unreadable(
        "Atlas owner",
        "the owner's worktree list lock is poisoned; restart the host, the index stores are kept",
    )
}

/// What one background pass found.
#[derive(Clone, Copy, Default)]
struct Pass {
    /// More record feed is waiting; run again soon.
    again: bool,
    /// A feed write failed (a writer busy with a rebuild); retry after a pause.
    backoff: bool,
    /// The catalogue changed; scan it on the next pass.
    rescan: bool,
}

impl Service {
    pub async fn run<T: Send + Sync + 'static>(
        self: Arc<Self>,
        host: Arc<dyn AtlasHost>,
        mut stopped: watch::Receiver<Option<T>>,
    ) -> Result<()> {
        let mut scan = true;
        loop {
            if stopped.borrow().is_some() {
                break;
            }
            let pass = if self.enabled {
                self.background(&host, scan).await
            } else {
                Pass::default()
            };
            scan = pass.rescan;
            // A catalogue left unscanned is due again, not on the next event;
            // a failed pass waits out its pause first.
            let retry = if pass.again || (pass.rescan && !pass.backoff) {
                Some(FEED_AGAIN)
            } else if pass.backoff {
                Some(FEED_BACKOFF)
            } else {
                None
            };
            let stop = {
                let stopped = stopped.changed();
                let core = host.records().changed();
                let timer = async {
                    if let Some(delay) = retry {
                        tokio::time::sleep(delay).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                let (mut stopped, mut core, mut timer) = (
                    std::pin::pin!(stopped),
                    std::pin::pin!(core),
                    std::pin::pin!(timer),
                );
                poll_fn(|cx| {
                    if let Poll::Ready(value) = stopped.as_mut().poll(cx) {
                        return Poll::Ready(value.is_err());
                    }
                    if core.as_mut().poll(cx).is_ready() || timer.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(false);
                    }
                    Poll::Pending
                })
                .await
            };
            if stop || stopped.borrow().is_some() {
                break;
            }
        }
        Ok(())
    }

    async fn background(self: &Arc<Self>, host: &Arc<dyn AtlasHost>, scan: bool) -> Pass {
        let service = self.clone();
        let job = host.clone();
        let work = host
            .run_background_owned(
                Duration::from_secs(5),
                Box::new(move || {
                    let pass = service.work(job.as_ref(), scan)?;
                    Ok(Box::new(pass) as Box<dyn Any + Send>)
                }),
            )
            .await
            .and_then(|value| {
                value
                    .downcast::<Pass>()
                    .map(|pass| *pass)
                    .map_err(|_| busy())
            });
        work.unwrap_or_else(|error| {
            eprintln!("Code index maintenance paused: {error}");
            // A failed pass may have taken registry activity it never acted
            // on, or left its catalogue scan unfinished: scan after the pause.
            Pass {
                backoff: true,
                rescan: true,
                ..Pass::default()
            }
        })
    }

    /// One bounded pass: register the catalogue when asked, then feed each
    /// started worktree its project's committed records, several chunks per
    /// worktree within [`FEED_PASS`].
    fn work(&self, host: &dyn AtlasHost, scan: bool) -> Result<Pass> {
        let mut pass = Pass::default();
        if let Some(activity) = host.records().take_activity()? {
            pass.rescan = activity.registry_changed || activity.overflow;
            if activity.overflow {
                // Lost activity names no project: every one may be behind.
                let all: Vec<ProjectId> = self
                    .roots()?
                    .iter()
                    .map(|registered| registered.spec.project.clone())
                    .collect();
                self.need_feed(all)?;
            }
            self.need_feed(activity.projects)?;
        }
        if scan {
            let mut catalogue = roots::Scan::default();
            let until = Instant::now() + Duration::from_secs(2);
            while !catalogue.page(host, &self.owner, self)? {
                if Instant::now() >= until {
                    pass.rescan = true;
                    break;
                }
            }
        }
        let started = self.started()?;
        let waiting = std::mem::take(&mut *self.feeding.lock().map_err(|_| busy())?);
        let until = Instant::now() + FEED_PASS;
        let mut unsettled = Vec::new();
        for project in waiting {
            let mut complete = true;
            for root in started.iter().filter(|root| root.spec().project == project) {
                complete &= self.feed(host, root, until, &mut pass);
            }
            if !complete {
                unsettled.push(project);
            }
        }
        let mut feeding = self.feeding.lock().map_err(|_| busy())?;
        // A project asked for during the pass is fed on the next one.
        pass.again |= !feeding.is_empty();
        for project in unsettled {
            if !feeding.contains(&project) {
                feeding.push(project);
            }
        }
        Ok(pass)
    }

    /// Feed one worktree until it is current, cannot progress, or the pass
    /// runs out of time. True once it is current.
    fn feed(&self, host: &dyn AtlasHost, root: &Root, until: Instant, pass: &mut Pass) -> bool {
        loop {
            match records::chunk(host, &self.owner, root) {
                Ok(records::Fed::Current) => return true,
                Ok(records::Fed::More) if Instant::now() < until => {}
                Ok(records::Fed::More | records::Fed::Waiting) => {
                    pass.again = true;
                    return false;
                }
                Err(error) => {
                    // A writer busy with a rebuild times the write out; retry
                    // after a pause so record lag clears without a new event.
                    pass.backoff = true;
                    eprintln!("Code index record feed paused: {error}");
                    return false;
                }
            }
        }
    }

    /// Mark projects whose records may be ahead of their engines.
    fn need_feed(&self, projects: impl IntoIterator<Item = ProjectId>) -> Result<()> {
        let mut feeding = self.feeding.lock().map_err(|_| busy())?;
        for project in projects {
            if !feeding.contains(&project) {
                feeding.push(project);
            }
        }
        Ok(())
    }

    /// Stop every worktree's writer: signal them all first, then join each
    /// within the shared deadline. One slow writer never leaves the others
    /// running; the first failure is reported after every join.
    pub async fn close(self: Arc<Self>, host: &dyn AtlasHost, remaining: Duration) -> Result<()> {
        let close_at = Instant::now() + remaining;
        host.run_owned(
            remaining,
            Box::new(move || {
                let started = self.started()?;
                for root in &started {
                    root.signal_stop();
                }
                let mut first = None;
                for root in &started {
                    if let Err(error) = root.join(close_at) {
                        first.get_or_insert(error);
                    }
                }
                first.map_or(Ok(()), Err)?;
                Ok(Box::new(()) as Box<dyn Any + Send>)
            }),
        )
        .await?;
        Ok(())
    }
}

fn close_read<T>(result: Result<T>, closed: se_store::StoreResult<()>) -> Result<T> {
    match (result, closed) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(store_error(&error)),
        (Err(original), Err(error)) => Err(original.with_cause(error)),
    }
}

fn admission(host: &dyn AtlasHost, owner: &HumanId, scope: Scope) -> Admission {
    Admission {
        scope,
        actor: Actor::Human(owner.clone()),
        session: None,
        generation: host.generation().get(),
    }
}
