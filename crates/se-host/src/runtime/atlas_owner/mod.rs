//! One after-ready Atlas driver on the supplied runtime and maintenance gate.
//! No IO starts during installation, and no SQL handle crosses an await.
mod qualification;
mod read;
mod records;
mod roots;
mod work;
use super::{ExecutionContext, HostedRuntime, executor};
use crate::atlas_renewal::{NativeRenewal, drive_events, drive_quantum};
use crate::atlas_runtime::project_work::{ProjectWork, Ticket};
use crate::atlas_runtime::{NativeController, NativeRuntime, read_port::*};
use se_atlas::{cache::connection::SqlProfile, lifecycle::*, model::*, parse::ParserProfile};
use se_core::store_error::store_error;
use se_store::{Actor, Admission, Scope, Snapshot};
use se_types::{HumanId, ProjectId, Result, SeError};
use std::future::{Future, poll_fn};
use std::os::fd::OwnedFd;
use std::task::Poll;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{io::unix::AsyncFd, sync::watch};

/// Independent native measurements supply these admissions. Installation fills
/// the measured Linux SQL/parser defaults within their qualified source bounds.
#[derive(Default, Debug)]
pub struct NativeAtlasQualification {
    pub sql: Option<SqlProfile>,
    pub parsers: Vec<ParserProfile>,
}
pub(super) struct Service {
    state: Mutex<State>,
    readers: Mutex<read::Catalogue>,
    profile: Option<SqlProfile>,
    owner: HumanId,
    memory: MemoryBudget,
    enabled: bool,
    interests: Arc<crate::atlas_runtime::record_fence::RecordFeedFence>,
    work: Arc<ProjectWork>,
    home: PathBuf,
}
struct State {
    controller: NativeController<NativeRenewal>,
    home: PathBuf,
    roots: Vec<Root>,
    scan: Option<roots::Scan>,
    enabled: bool,
    child_deadline: Option<(u32, Instant)>,
    work: Arc<ProjectWork>,
    queue_scan: Option<crate::atlas_runtime::project_work::Scan>,
    active_project: Option<ActiveProject>,
    registry_dirty: bool,
    reconcile_all: bool,
}
struct ActiveProject {
    ticket: Ticket,
    after: Option<RootId>,
    root: Option<RootId>,
}
struct Root {
    registration: RootRegistration,
    feed_pending: bool,
    feed_stalled: bool,
}
#[derive(Clone)]
enum Wake {
    Core,
    Source(RootId),
    Child,
    Scheduled,
}
struct Plan {
    ready: bool,
    delay: Option<Duration>,
    fds: Vec<(OwnedFd, Wake)>,
}
impl HostedRuntime {
    /// Standalone installation, before listen. The service
    /// begins only in serve, after readiness has been published.
    pub fn install_native_atlas(
        &mut self,
        image: PathBuf,
        qualification: NativeAtlasQualification,
    ) -> Result<()> {
        if self.kind != crate::HostKind::Standalone
            || self.phase != crate::HostPhase::Prepared
            || self.atlas_owner.is_some()
        {
            return Err(SeError::invalid(
                "Atlas owner",
                "one standalone installation before listener publication; embedded hosts do not run Atlas",
            ));
        }
        let enabled = self
            .configuration
            .as_ref()
            .ok_or_else(|| {
                SeError::invalid(
                    "Atlas configuration",
                    "resolved host configuration before Atlas installation",
                )
            })?
            .atlas
            .enabled;
        let qualification = qualification.with_native_sql()?;
        let home = self.state_directory.join("atlas");
        let work = Arc::new(ProjectWork::new(
            self.state_directory.join("atlas-projects"),
        ));
        let memory = qualification.memory();
        let profile = qualification.sql.clone();
        let controller = NativeController::new(NativeRuntime::new(
            home.clone(),
            image,
            NativeRenewal::new(qualification.parsers)?,
            qualification.sql,
        )?);
        let service = Arc::new(Service {
            state: Mutex::new(State {
                controller,
                home: home.clone(),
                roots: Vec::new(),
                scan: Some(roots::Scan::default()),
                enabled,
                child_deadline: None,
                work: work.clone(),
                queue_scan: None,
                active_project: None,
                registry_dirty: false,
                reconcile_all: false,
            }),
            readers: Mutex::new(read::Catalogue::default()),
            profile,
            owner: self.owner.clone(),
            memory,
            enabled,
            interests: self.execution.atlas.records.clone(),
            work,
            home,
        });
        self.install_atlas_read_port(service.clone())?;
        self.atlas_owner = Some(service);
        Ok(())
    }
}
fn busy() -> SeError {
    se_core::scope::unreadable(
        "Atlas owner",
        "the maintenance owner lock is poisoned; preserve the cache and restart the host",
    )
}
impl Service {
    pub(super) async fn run(
        self: Arc<Self>,
        context: ExecutionContext,
        mut stopped: watch::Receiver<Option<crate::client::lease::Deadline>>,
    ) -> Result<()> {
        let mut wake = Wake::Core;
        loop {
            if stopped.borrow().is_some() {
                break;
            }
            let service = self.clone();
            let job = context.clone();
            let deadline = deadline(Duration::from_secs(5))?;
            let work = context
                .blocking
                .run_background_owned(&deadline, move || {
                    let mut state = service.state.lock().map_err(|_| busy())?;
                    service.publish_readers(&state, true)?;
                    let result = state.work(&job, &service.owner, wake);
                    service.publish_readers(&state, false)?;
                    result
                })
                .await;
            let plan = match work {
                Ok(plan) => plan,
                Err(error) => {
                    eprintln!("Code index maintenance paused: {error}");
                    // No retry timer is invented after failure. A new committed
                    // event can retry independently of source readiness.
                    Plan {
                        ready: false,
                        delay: None,
                        fds: Vec::new(),
                    }
                }
            };
            enum Event {
                Stop(bool),
                Core,
                Ready(Result<Wake>),
            }
            let event = {
                let stopped = stopped.changed();
                let core = context.atlas.records.changed();
                let ready = wait(plan);
                let mut stopped = std::pin::pin!(stopped);
                let mut core = std::pin::pin!(core);
                let mut ready = std::pin::pin!(ready);
                poll_fn(|cx| {
                    if let Poll::Ready(value) = stopped.as_mut().poll(cx) {
                        return Poll::Ready(Event::Stop(value.is_err()));
                    }
                    if core.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Event::Core);
                    }
                    if let Poll::Ready(value) = ready.as_mut().poll(cx) {
                        return Poll::Ready(Event::Ready(value));
                    }
                    Poll::Pending
                })
                .await
            };
            match event {
                Event::Stop(closed) => {
                    if closed || stopped.borrow().is_some() {
                        break;
                    }
                    wake = Wake::Scheduled;
                }
                Event::Core => wake = Wake::Core,
                Event::Ready(ready) => wake = ready?,
            }
        }
        Ok(())
    }
    pub(super) async fn close(
        self: Arc<Self>,
        context: &ExecutionContext,
        bound: &crate::client::lease::Deadline,
    ) -> Result<()> {
        let close_bound = bound.clone();
        context.blocking.run_owned(bound,move || {
            self.readers.lock().map_err(|_| read::poisoned())?.clear();
            let mut state=self.state.lock().map_err(|_|busy())?;
            let roots:Vec<_>=state.roots.iter().map(|r|r.registration.root.clone()).collect();
            for root in roots {
                match state.controller.close(root,CloseReason::HostDrain,close_bound.remaining()?)? {
                    CloseResult::Closed=>(),
                    _=>return Err(SeError::invalid("Atlas shutdown", "native child and watch close must complete before the owner releases custody")),
                }
            }
            Ok(())
        }).await
    }
}
async fn wait(plan: Plan) -> Result<Wake> {
    if plan.ready {
        tokio::task::yield_now().await;
        return Ok(Wake::Scheduled);
    }
    let fds: Vec<_> = plan
        .fds
        .into_iter()
        .map(|(fd, wake)| {
            #[expect(deprecated, reason = "The reactor exclusively owns this OwnedFd until AsyncFd drops it; its descriptor is fixed, unlike a generic AsRawFd value. Native unsafe code stays in se-proc.")]
            let registration=AsyncFd::with_interest(fd,tokio::io::Interest::READABLE);
            registration.map(|fd|(fd,wake))
        })
        .collect::<std::io::Result<_>>()
        .map_err(|e| se_core::scope::unreadable("Atlas readiness", &e.to_string()))?;
    let readable = std::future::poll_fn(|cx| {
        for (fd, wake) in &fds {
            match fd.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(mut ready)) => {
                    ready.clear_ready();
                    return std::task::Poll::Ready(Ok(wake.clone()));
                }
                std::task::Poll::Ready(Err(error)) => {
                    return std::task::Poll::Ready(Err(se_core::scope::unreadable(
                        "Atlas readiness",
                        &error.to_string(),
                    )));
                }
                std::task::Poll::Pending => (),
            }
        }
        std::task::Poll::Pending
    });
    let timer = async {
        match plan.delay {
            Some(delay) => tokio::time::sleep(delay).await,
            None => std::future::pending().await,
        };
        Ok(Wake::Scheduled)
    };
    let mut readable = std::pin::pin!(readable);
    let mut timer = std::pin::pin!(timer);
    poll_fn(|cx| {
        if let Poll::Ready(value) = timer.as_mut().poll(cx) {
            return Poll::Ready(value);
        }
        readable.as_mut().poll(cx)
    })
    .await
}
fn deadline(timeout: Duration) -> Result<crate::client::lease::Deadline> {
    crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
        expected_generation: None,
        timeout,
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
}
fn admission(context: &ExecutionContext, owner: &HumanId, scope: Scope) -> Admission {
    Admission {
        scope,
        actor: Actor::Human(owner.clone()),
        session: None,
        generation: context.generation.get(),
    }
}
