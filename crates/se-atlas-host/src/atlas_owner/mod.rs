//! One after-ready Atlas driver on the supplied runtime and maintenance gate.
//! No IO starts during installation, and no SQL handle crosses an await.
mod qualification;
mod read;
mod records;
mod roots;
mod work;
use crate::atlas_renewal::{NativeRenewal, drive_events, drive_quantum};
use crate::atlas_runtime::project_work::{ProjectWork, Ticket};
use crate::atlas_runtime::{NativeController, NativeRuntime, read_port::*};
use crate::host::AtlasHost;
use se_atlas::{cache::connection::SqlProfile, lifecycle::*, model::*, parse::ParserProfile};
use se_core::store_error::store_error;
use se_store::{Actor, Admission, Scope, Snapshot};
use se_types::{HumanId, ProjectId, Result, SeError};
use std::future::{Future, poll_fn};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::task::Poll;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

/// Independent native measurements supply these admissions. Installation fills
/// the measured Linux SQL/parser defaults within their qualified source bounds.
#[derive(Default, Debug)]
pub struct NativeAtlasQualification {
    pub sql: Option<SqlProfile>,
    pub parsers: Vec<ParserProfile>,
}
pub struct Service {
    #[cfg(windows)]
    source_signal: Arc<tokio::sync::Notify>,
    state: Mutex<State>,
    readers: Mutex<read::Catalogue>,
    profile: Option<SqlProfile>,
    owner: HumanId,
    memory: MemoryBudget,
    enabled: bool,
    unqualified: bool,
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
    work_retry_after: Option<Instant>,
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
    // Deadline, previous delay, and whether this is the final native drain.
    event_retry: Option<(Instant, Duration, bool)>,
}
#[derive(Clone)]
enum Wake {
    Core,
    #[cfg(target_os = "linux")]
    Source(RootId),
    #[cfg(windows)]
    Sources,
    #[cfg(target_os = "linux")]
    Child,
    Scheduled,
}
struct Plan {
    ready: bool,
    delay: Option<Duration>,
    #[cfg(windows)]
    listen_sources: bool,
    #[cfg(target_os = "linux")]
    fds: Vec<(OwnedFd, Wake)>,
}
impl Service {
    pub fn new(
        state_directory: &std::path::Path,
        image: PathBuf,
        owner: HumanId,
        enabled: bool,
        qualification: NativeAtlasQualification,
        interests: Arc<crate::atlas_runtime::record_fence::RecordFeedFence>,
    ) -> Result<Arc<Self>> {
        let qualification = qualification.with_native_sql()?;
        let unqualified = cfg!(windows) && enabled && qualification.sql.is_none();
        let enabled = enabled && !unqualified;
        let home = state_directory.join("atlas");
        let work = Arc::new(ProjectWork::new(state_directory.join("atlas-projects")));
        let memory = qualification.memory();
        let profile = qualification.sql.clone();
        let renewal = NativeRenewal::new(qualification.parsers)?;
        #[cfg(windows)]
        let source_signal = renewal.signal();
        let controller = NativeController::new(NativeRuntime::new(
            home.clone(),
            image,
            renewal,
            qualification.sql,
        )?);
        Ok(Arc::new(Self {
            #[cfg(windows)]
            source_signal,
            state: Mutex::new(State {
                controller,
                home: home.clone(),
                roots: Vec::new(),
                scan: Some(roots::Scan::default()),
                enabled,
                child_deadline: None,
                work_retry_after: None,
                work: work.clone(),
                queue_scan: None,
                active_project: None,
                registry_dirty: false,
                reconcile_all: false,
            }),
            readers: Mutex::new(read::Catalogue::default()),
            profile,
            owner,
            memory,
            enabled,
            unqualified,
            interests,
            work,
            home,
        }))
    }
}
fn busy() -> SeError {
    se_core::scope::unreadable(
        "Atlas owner",
        "the maintenance owner lock is poisoned; preserve the cache and restart the host",
    )
}
impl Service {
    pub async fn run<T: Send + Sync + 'static>(
        self: Arc<Self>,
        host: Arc<dyn AtlasHost>,
        mut stopped: watch::Receiver<Option<T>>,
    ) -> Result<()> {
        let mut wake = Wake::Core;
        loop {
            if stopped.borrow().is_some() {
                break;
            }
            let service = self.clone();
            let job = host.clone();
            let work = host
                .run_background_owned(
                    Duration::from_secs(5),
                    Box::new(move || {
                        let mut state = service.state.lock().map_err(|_| busy())?;
                        service.publish_readers(&state, true)?;
                        let result = state.work(job.as_ref(), &service.owner, wake);
                        service.publish_readers(&state, false)?;
                        // Keep live progress in memory. Only a settled pass needs
                        // durable metadata for readers of a later cold root.
                        let pending = result
                            .as_ref()
                            .is_ok_and(|plan| plan.ready || plan.delay.is_some());
                        if !pending {
                            service.persist_readers()?;
                        }
                        Ok(Box::new(result?) as Box<dyn std::any::Any + Send>)
                    }),
                )
                .await
                .and_then(|value| {
                    value
                        .downcast::<Plan>()
                        .map(|boxed| *boxed)
                        .map_err(|_| busy())
                });
            let plan = match work {
                Ok(plan) => plan,
                Err(error) => {
                    eprintln!("Code index maintenance paused: {error}");
                    // No retry timer is invented after failure. A new committed
                    // event can retry independently of source readiness.
                    Plan {
                        ready: false,
                        delay: None,
                        #[cfg(windows)]
                        listen_sources: false,
                        #[cfg(target_os = "linux")]
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
                let core = host.records().changed();
                #[cfg(windows)]
                let listen_sources = plan.listen_sources;
                let ready = wait(plan);
                #[cfg(windows)]
                let source = self.source_signal.notified();
                let mut stopped = std::pin::pin!(stopped);
                let mut core = std::pin::pin!(core);
                let mut ready = std::pin::pin!(ready);
                #[cfg(windows)]
                let mut source = std::pin::pin!(source);
                poll_fn(|cx| {
                    if let Poll::Ready(value) = stopped.as_mut().poll(cx) {
                        return Poll::Ready(Event::Stop(value.is_err()));
                    }
                    if core.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Event::Core);
                    }
                    #[cfg(windows)]
                    if listen_sources && source.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Event::Ready(Ok(Wake::Sources)));
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
    pub async fn close(self: Arc<Self>, host: &dyn AtlasHost, remaining: Duration) -> Result<()> {
        let close_at = Instant::now() + remaining;
        host.run_owned(
            remaining,
            Box::new(move || {
                self.readers.lock().map_err(|_| read::poisoned())?.clear();
                let mut state = self.state.lock().map_err(|_| busy())?;
                let roots: Vec<_> = state
                    .roots
                    .iter()
                    .map(|r| r.registration.root.clone())
                    .collect();
                for root in roots {
                    let left = close_at
                        .checked_duration_since(Instant::now())
                        .filter(|d| !d.is_zero())
                        .ok_or_else(|| {
                            SeError::new(se_types::Detail::DeadlineExceeded(
                                se_types::details::DeadlineExceeded {
                                    op: "local IPC".into(),
                                    deadline_ms: remaining.as_millis().min(u128::from(u64::MAX))
                                        as u64,
                                },
                            ))
                        })?;
                    match state.controller.close(root, CloseReason::HostDrain, left)? {
                        CloseResult::Closed => (),
                        _ => {
                            return Err(SeError::invalid(
                                "Atlas shutdown",
                                "native child and watch close must complete before the owner releases custody",
                            ));
                        }
                    }
                }
                Ok(Box::new(()) as Box<dyn std::any::Any + Send>)
            }),
        )
        .await?;
        Ok(())
    }
}
#[cfg(target_os = "linux")]
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
#[cfg(windows)]
async fn wait(plan: Plan) -> Result<Wake> {
    if plan.ready {
        tokio::task::yield_now().await;
    } else if let Some(delay) = plan.delay {
        tokio::time::sleep(delay).await;
    } else {
        std::future::pending::<()>().await;
    }
    Ok(Wake::Scheduled)
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
