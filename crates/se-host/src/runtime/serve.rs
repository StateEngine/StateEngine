//! One supplied-runtime listener/dispatch supervisor. The returned owner retains
//! every shutdown obligation; an ended loop never claims a native close witness.
use super::*;
use crate::client::{
    ClientOptions,
    lease::{CALL_TIMEOUT, Deadline, HELLO_TIMEOUT},
};
use se_types::{Result, SeError};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};
use tokio::{sync::watch, task::JoinSet};

pub struct HostServeExit {
    pub runtime: HostedRuntime,
    pub listener: HostedListener,
    pub stop: Option<Box<AuthorizedStop>>,
    pub failure: Option<SeError>,
    /// None means the finite counter was exhausted, never a fabricated zero.
    pub failed_connections: Option<u64>,
    /// Bounded diagnostic state; the count above names prior failures too.
    pub last_connection_error: Option<se_types::ErrorBody>,
}
enum ConnectionEnd {
    Closed,
    Cancelled,
    Stop(Box<AuthorizedStop>),
    CatchUp(Result<()>),
}
#[allow(
    clippy::large_enum_variant,
    reason = "One bounded supervisor stack value avoids a heap allocation on every accept."
)]
enum Event {
    Accepted(Result<crate::AcceptedIpcStream>),
    Http(Result<(tokio::net::TcpStream, tokio::sync::OwnedSemaphorePermit)>),
    /// The embedder's in-process stop; the same fence and join as any stop.
    LocalStop,
    /// An automatically started host stayed at zero activity for the full window.
    IdleExpired,
    CatchUp,
    OwnershipFault,
    Joined(std::result::Result<Result<ConnectionEnd>, tokio::task::JoinError>),
}
impl HostedRuntime {
    /// OS accept, bounded per-connection authentication and the sole core/store
    /// executor all share the supplied runtime. No callback/dispatcher or runtime
    /// is manufactured here. On stop/fault, fence and join accepted tasks first.
    pub async fn serve(mut self, mut listener: HostedListener) -> HostServeExit {
        let router = match self.router() {
            Ok(router)
                if listener.endpoint().epoch == self.epoch
                    && listener.endpoint().generation == self.generation() =>
            {
                router
            }
            Ok(_) => {
                return ended(
                    self,
                    listener,
                    Some(SeError::invalid(
                        "host listener",
                        "this exact epoch and committed generation",
                    )),
                );
            }
            Err(error) => return ended(self, listener, Some(error)),
        };
        let runtime = self.execution.blocking.handle();
        // Provider MCP sessions reach this host over the loopback HTTP listener
        // bound at publication, before readiness was reported.
        let Some(http) = self.http.take() else {
            let error = SeError::invalid(
                "loopback HTTP listener",
                "one bound at listener publication",
            );
            return ended(self, listener, Some(error));
        };
        let mut local_stop = self.local_stop.take();
        let activity = self.activity.clone();
        let mut catch_up_running = false;
        // Only an automatically started host with a known activity count may
        // exit when idle; an explicit `se up` or an unknown count stays resident.
        // Built once: unrelated traffic must not restart its zero-activity window.
        let mut idle: std::pin::Pin<Box<dyn Future<Output = ()> + Send>> =
            match self.auto_start.then(|| self.activity.take()).flatten() {
                Some(mut activity) => Box::pin(async move { idle_expiry(&mut activity).await }),
                None => Box::pin(std::future::pending()),
            };
        let (shutdown, cancelled) = watch::channel(None);
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            idle = Box::pin(super::memory::while_serving(
                idle,
                self.memory_reclaim.clone(),
            ));
        }
        let mut tasks = JoinSet::new();
        let mut timers = super::live::Timers::new(
            idle,
            activity.clone(),
            self.execution.ownership_fault.clone(),
        );
        let mut accept_backoff = std::time::Duration::from_millis(1);
        let mut accept_retry_at = tokio::time::Instant::now();
        let mut http_backoff = std::time::Duration::from_millis(1);
        let mut http_retry_at = tokio::time::Instant::now();
        let mut outcome = loop {
            match event(
                &mut listener,
                &http,
                &mut tasks,
                local_stop.as_mut(),
                &mut timers,
                accept_retry_at,
                http_retry_at,
            )
            .await
            {
                Event::LocalStop | Event::IdleExpired => break ended(self, listener, None),
                Event::OwnershipFault => {
                    break ended(
                        self,
                        listener,
                        Some(se_core::scope::unreadable(
                            "writer/native collector ownership",
                            "the writer or shared collector failed; this generation is fenced and retains custody for controlled recovery",
                        )),
                    );
                }
                Event::CatchUp => {
                    timers.catch_up = super::live::timer(activity.clone());
                    if !catch_up_running
                        && let Some(custody) = self.execution.custody.get().cloned()
                    {
                        catch_up_running = true;
                        tasks.spawn_on(
                            async move {
                                let result = match options(CALL_TIMEOUT) {
                                    Ok(deadline) => custody.catch_up(&deadline).await,
                                    Err(error) => Err(error),
                                };
                                Ok(ConnectionEnd::CatchUp(result))
                            },
                            &runtime,
                        );
                    }
                }
                Event::Accepted(Ok(stream)) => {
                    if let Err(error) = self.execution.ownership_fault.route("IPC listener", false)
                    {
                        self.failed_connection(error);
                    }
                    accept_backoff = std::time::Duration::from_millis(1);
                    let router = router.clone();
                    let cancelled = cancelled.clone();
                    tasks.spawn_on(connection(router, stream, cancelled), &runtime);
                }
                Event::Accepted(Err(error)) if transient_accept(&error) => {
                    self.failed_connection(error);
                    accept_retry_at = tokio::time::Instant::now() + accept_backoff;
                    accept_backoff =
                        (accept_backoff * 2).min(std::time::Duration::from_millis(250));
                }
                Event::Accepted(Err(error)) => {
                    self.failed_connection(error);
                    if let Err(error) = self.execution.ownership_fault.route("IPC listener", true) {
                        self.failed_connection(error);
                    }
                    accept_retry_at =
                        tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                }
                Event::Http(Ok((stream, permit))) => {
                    if let Err(error) = self.execution.ownership_fault.route("HTTP listener", false)
                    {
                        self.failed_connection(error);
                    }
                    http_backoff = std::time::Duration::from_millis(1);
                    let (router, cancelled, port) =
                        (router.clone(), cancelled.clone(), http.port());
                    let served = async move {
                        crate::http::connection(router, stream, port, permit, cancelled)
                            .await
                            .map(|()| ConnectionEnd::Closed)
                    };
                    tasks.spawn_on(served, &runtime);
                }
                Event::Http(Err(error)) if transient_accept(&error) => {
                    self.failed_connection(error);
                    http_retry_at = tokio::time::Instant::now() + http_backoff;
                    http_backoff = (http_backoff * 2).min(std::time::Duration::from_millis(250));
                }
                Event::Http(Err(error)) => {
                    self.failed_connection(error);
                    if let Err(error) = self.execution.ownership_fault.route("HTTP listener", true)
                    {
                        self.failed_connection(error);
                    }
                    http_retry_at =
                        tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                }
                Event::Joined(Ok(Ok(ConnectionEnd::Stop(stop)))) => {
                    let mut exit = ended(self, listener, None);
                    exit.stop = Some(stop);
                    break exit;
                }
                Event::Joined(Ok(Ok(ConnectionEnd::CatchUp(result)))) => {
                    catch_up_running = false;
                    if let Err(error) = result {
                        self.failed_connection(error);
                    }
                }
                Event::Joined(Ok(Ok(ConnectionEnd::Closed | ConnectionEnd::Cancelled))) =>
                {
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    if let Some(memory) = &self.memory_reclaim {
                        memory.completed();
                    }
                }
                Event::Joined(Ok(Err(error))) => {
                    self.failed_connection(error);
                }
                Event::Joined(Err(error)) => {
                    self.failed_connection(
                        se_core::scope::unreadable("host connection task", &error.to_string())
                            .with_cause(error),
                    );
                    catch_up_running = false;
                }
            }
        };
        outcome.runtime.fenced.store(true, Ordering::Release);
        if let Err(error) = outcome.runtime.execution.mail_waits.close() {
            outcome.failure.get_or_insert(error);
        }
        outcome.runtime.phase = crate::HostPhase::Draining;
        // Waiting for the next request is cancellable; an admitted request owns
        // its execution and reply until completion. Charge that join against the
        // same shutdown budget used by storage drain, rather than renewing it.
        outcome.runtime.shutdown_deadline = match options(CALL_TIMEOUT) {
            Ok(deadline) => Some(deadline),
            Err(error) => {
                outcome.failure.get_or_insert(error);
                None
            }
        };
        shutdown.send_replace(outcome.runtime.shutdown_deadline.clone());
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(ConnectionEnd::Stop(stop))) => {
                    // A second authenticated stop raced the fence. Its original
                    // control request is refused, never relabelled as success.
                    let error = SeError::invalid(
                        "runtime stop",
                        "the already admitted shutdown result; preserve this original key and rediscover",
                    );
                    let reply = crate::client::endpoint::RuntimeStopReply {
                        epoch: stop.request().expected_epoch.clone(),
                        generation: stop.request().generation,
                        key: stop.request().key.clone(),
                        outcome: crate::client::endpoint::RuntimeStopOutcome::Refused {
                            error: match se_types::ErrorEnvelope::new(
                                error.body,
                                &se_types::RenderCx::default(),
                            ) {
                                Ok(envelope) => envelope,
                                Err(error) => {
                                    outcome.runtime.failed_connection(error);
                                    continue;
                                }
                            },
                        },
                    };
                    match outcome
                        .runtime
                        .shutdown_deadline
                        .as_ref()
                        .cloned()
                        .map_or_else(|| options(CALL_TIMEOUT), Ok)
                    {
                        Ok(deadline) => {
                            if let Err(error) = stop.reply(&reply, &deadline).await {
                                outcome.runtime.failed_connection(error);
                            }
                        }
                        Err(error) => outcome.runtime.failed_connection(error),
                    }
                }
                Ok(Err(error)) => outcome.runtime.failed_connection(error),
                Ok(Ok(ConnectionEnd::CatchUp(Err(error)))) => {
                    outcome.runtime.failed_connection(error)
                }
                Err(error) => {
                    outcome.failure.get_or_insert_with(|| {
                        se_core::scope::unreadable("joined host task", &error.to_string())
                    });
                }
                _ => (),
            }
        }
        outcome.failed_connections = outcome.runtime.connection_failures;
        outcome.last_connection_error = outcome.runtime.last_connection_error.clone();
        outcome
    }
    fn failed_connection(&mut self, error: SeError) {
        // None explicitly reports counter exhaustion rather than a false exact
        // count or a fabricated zero; the last concrete failure stays retained.
        self.connection_failures = self
            .connection_failures
            .and_then(|count| count.checked_add(1));
        self.last_connection_error = Some(error.body);
    }
}
fn ended(
    runtime: HostedRuntime,
    listener: HostedListener,
    failure: Option<SeError>,
) -> HostServeExit {
    HostServeExit {
        failed_connections: runtime.connection_failures,
        last_connection_error: runtime.last_connection_error.clone(),
        runtime,
        listener,
        stop: None,
        failure,
    }
}
async fn event(
    listener: &mut HostedListener,
    http: &crate::HttpListener,
    tasks: &mut JoinSet<Result<ConnectionEnd>>,
    local_stop: Option<&mut watch::Receiver<bool>>,
    timers: &mut super::live::Timers,
    retry_at: tokio::time::Instant,
    http_retry_at: tokio::time::Instant,
) -> Event {
    let mut accepting = pin!(async {
        tokio::time::sleep_until(retry_at).await;
        listener.accept(Arc::new(AtomicBool::new(false))).await
    });
    let mut http_accepting = pin!(async {
        tokio::time::sleep_until(http_retry_at).await;
        http.accept().await
    });
    // A request or a dropped handle stops the host: an embedder that lost its
    // only in-process stop (a cancelled activation, a factory dropped without
    // drain) could never stop this generation otherwise.
    let mut stopping = pin!(async move {
        match local_stop {
            Some(stop) => drop(stop.wait_for(|requested| *requested).await),
            None => std::future::pending::<()>().await,
        }
    });
    poll_fn(|cx| {
        if stopping.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Event::LocalStop);
        }
        if let Poll::Ready(tick) = timers.poll(cx) {
            return Poll::Ready(match tick {
                super::live::Tick::Idle => Event::IdleExpired,
                super::live::Tick::CatchUp => Event::CatchUp,
                super::live::Tick::OwnershipFault => Event::OwnershipFault,
            });
        }
        if !tasks.is_empty()
            && let Poll::Ready(Some(joined)) = tasks.poll_join_next(cx)
        {
            return Poll::Ready(Event::Joined(joined));
        }
        if let Poll::Ready(accepted) = http_accepting.as_mut().poll(cx) {
            return Poll::Ready(Event::Http(accepted));
        }
        accepting.as_mut().poll(cx).map(Event::Accepted)
    })
    .await
}
async fn until_shutdown<T>(
    work: impl Future<Output = Result<T>>,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<Option<T>> {
    if shutdown.borrow().is_some() {
        return Ok(None);
    }
    let mut work = pin!(work);
    let mut cancelled = pin!(shutdown.changed());
    poll_fn(|cx| {
        if cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(None));
        }
        work.as_mut().poll(cx).map(|result| result.map(Some))
    })
    .await
}
async fn connection(
    router: HostedRouter,
    stream: crate::AcceptedIpcStream,
    mut shutdown: watch::Receiver<Option<Deadline>>,
) -> Result<ConnectionEnd> {
    let hello = options(HELLO_TIMEOUT)?;
    let Some(peer) =
        until_shutdown(router.authenticate_stream(stream, &hello), &mut shutdown).await?
    else {
        return Ok(ConnectionEnd::Cancelled);
    };
    let mut connection = match peer {
        AcceptedPeer::Stop(stop) => return Ok(ConnectionEnd::Stop(stop)),
        AcceptedPeer::Operation(connection) => *connection,
    };
    loop {
        let idle = Deadline::idle()?;
        let Some(next) =
            until_shutdown(router.read_call_idle(connection, &idle), &mut shutdown).await?
        else {
            return Ok(ConnectionEnd::Cancelled);
        };
        let Some((mut exchange, deadline)) = next else {
            return Ok(ConnectionEnd::Closed);
        };
        let output = match exchange.take_call() {
            Ok(call) => router.execute_call(call, &deadline).await,
            Err(error) => Err(error),
        };
        // An expired execution clock may already carry the known-commit error.
        // Keep the channel alive to deliver it within the shutdown's remaining
        // budget instead of losing that fact to an expired request clock.
        let draining = shutdown.borrow().clone();
        connection = match draining {
            Some(bound) => exchange.reply_draining(output, &bound).await?,
            None => exchange.reply(output, &deadline).await?,
        };
    }
}
fn options(timeout: std::time::Duration) -> Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}

fn transient_accept(error: &SeError) -> bool {
    use std::error::Error;
    let mut cause = error.source();
    while let Some(value) = cause {
        if let Some(error) = value.downcast_ref::<std::io::Error>() {
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::OutOfMemory
            ) {
                return true;
            }
            #[cfg(unix)]
            if matches!(error.raw_os_error(), Some(12 | 23 | 24 | 105)) {
                return true;
            }
            #[cfg(windows)]
            if matches!(error.raw_os_error(), Some(4 | 8 | 14 | 231 | 232 | 233)) {
                return true;
            }
        }
        cause = value.source();
    }
    false
}

/// An embedder's in-process stop for one hosted runtime; standalone hosts stop
/// only over the authenticated IPC control exchange.
pub struct LocalStop(watch::Sender<bool>);
impl LocalStop {
    pub fn request(&self) {
        self.0.send_replace(true);
    }
}
impl HostedRuntime {
    /// Take before `serve`; requesting or dropping it fences and joins like
    /// any stop.
    pub fn local_stop(&mut self) -> LocalStop {
        let (sender, receiver) = watch::channel(false);
        self.local_stop = Some(receiver);
        LocalStop(sender)
    }
}

/// An automatically started host exits after this long at zero activity
/// (section 40 §10.1); any activity restarts the window.
pub const AUTO_EXIT_IDLE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Resolve only after the activity count has stayed zero for the whole window,
/// rechecked at expiry. A closed activity source never ends the host.
async fn idle_expiry(activity: &mut watch::Receiver<u32>) {
    loop {
        if activity.wait_for(|count| *count == 0).await.is_err() {
            return std::future::pending().await;
        }
        // Any activity inside the window restarts it; expiry is rechecked.
        // The watch guard is released before the count is read again.
        let woke = tokio::time::timeout(AUTO_EXIT_IDLE, activity.wait_for(|count| *count != 0))
            .await
            .map(|seen| seen.map(drop));
        match woke {
            Err(_) if *activity.borrow() == 0 => return,
            Err(_) | Ok(Ok(())) => continue,
            Ok(Err(_)) => return std::future::pending().await,
        }
    }
}
impl HostedRuntime {
    /// Before listener publication: true only for a host started on demand
    /// (a launch, a hook, an SE Code handback), never an explicit `se up`.
    pub fn configure_auto_start(&mut self, enabled: bool) -> Result<()> {
        if self.phase != crate::HostPhase::Prepared {
            return Err(SeError::invalid(
                "host start origin",
                "a prepared runtime before listener publication",
            ));
        }
        self.auto_start = enabled;
        Ok(())
    }
    /// Before serve: the coordinator's live process/cleanup count. Zero is the
    /// only input that can start the idle window.
    pub fn attach_activity(&mut self, activity: watch::Receiver<u32>) {
        self.activity = Some(activity);
    }
    /// After the listener (and so the loopback port) is bound and before serve:
    /// one native coordinator for every hosted call, with its activity count
    /// for the idle window. Both startup paths install through here.
    pub fn install_custody(
        &mut self,
        custody: std::sync::Arc<dyn super::CustodyExecutor>,
        activity: watch::Receiver<u32>,
    ) -> Result<()> {
        if self.http_port.get().is_none() {
            return Err(SeError::invalid(
                "native coordinator",
                "installation after the loopback listener is bound",
            ));
        }
        self.execution.custody.set(custody).map_err(|_| {
            SeError::invalid("native coordinator", "one coordinator per hosted runtime")
        })?;
        self.attach_activity(activity);
        Ok(())
    }
    /// What the coordinator's opener needs from this runtime.
    pub fn execution_context(&self) -> super::ExecutionContext {
        self.execution.clone()
    }
    pub fn transcript_bindings(&self) -> super::TranscriptBindings {
        self.sources.clone()
    }
    pub fn configuration(&self) -> Option<&se_core::config_policy::ConfigFile> {
        self.configuration.as_ref()
    }
}
