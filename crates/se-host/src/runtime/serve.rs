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
mod fence;
mod supervisor;
type Idle = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;
use supervisor::Supervisor;

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
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Atlas(Result<()>),
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
        let idle = self.idle_window();
        let (shutdown, cancelled) = watch::channel(None);
        let mut supervisor = Supervisor::new(
            router,
            runtime.clone(),
            cancelled.clone(),
            http.port(),
            activity.clone(),
        );
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        if let Some(service) = self.atlas_owner.clone() {
            let context = self.execution.clone();
            let stopped = cancelled.clone();
            supervisor.tasks.spawn_on(
                async move {
                    Ok(ConnectionEnd::Atlas(
                        super::atlas_owner::run(service, context, stopped).await,
                    ))
                },
                &runtime,
            );
        }
        let mut timers =
            super::live::Timers::new(idle, activity, self.execution.ownership_fault.clone());
        let mut outcome = loop {
            let event = event(
                &mut listener,
                &http,
                &mut supervisor.tasks,
                local_stop.as_mut(),
                &mut timers,
                supervisor.accept.retry_at,
                supervisor.http.retry_at,
            )
            .await;
            if let Some((failure, stop)) = supervisor.handle(&mut self, &mut timers, event) {
                let mut exit = ended(self, listener, failure);
                exit.stop = stop;
                break exit;
            }
        };
        outcome.fence_and_join(supervisor.tasks, &shutdown).await;
        outcome
    }
    /// Only an automatically started host with a known activity count may exit
    /// when idle; any other host's window never expires.
    fn idle_window(&mut self) -> Idle {
        // Only an automatically started host with a known activity count may
        // exit when idle; an explicit `se up` or an unknown count stays resident.
        // Built once: unrelated traffic must not restart its zero-activity window.
        let idle: Idle = match self.auto_start.then(|| self.activity.take()).flatten() {
            Some(mut activity) => {
                let waits = self.execution.mail_waits.clone();
                Box::pin(async move {
                    super::client_activity::idle(waits, &mut activity).await;
                })
            }
            None => Box::pin(std::future::pending()),
        };
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let idle: Idle = Box::pin(super::memory::while_serving(
            idle,
            self.memory_reclaim.clone(),
        ));
        idle
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
    let connection = match peer {
        AcceptedPeer::Stop(stop) => return Ok(ConnectionEnd::Stop(stop)),
        AcceptedPeer::Rebound => return Ok(ConnectionEnd::Closed),
        AcceptedPeer::Operation(connection) => *connection,
    };
    let ext_claim = connection.grant.external_claim.clone();
    let ext_active = Arc::clone(&connection.grant.external_active);
    let outcome = connection_loop(&router, connection, &mut shutdown).await;
    crate::external::dispatch::release_connection(&router, ext_claim, &ext_active).await;
    outcome
}

async fn connection_loop(
    router: &HostedRouter,
    mut connection: HostedConnection,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<ConnectionEnd> {
    loop {
        let idle = Deadline::idle()?;
        let Some(next) = until_shutdown(router.read_call_idle(connection, &idle), shutdown).await?
        else {
            return Ok(ConnectionEnd::Cancelled);
        };
        let Some((mut exchange, deadline)) = next else {
            return Ok(ConnectionEnd::Closed);
        };
        if let Some(call) = exchange.take_external() {
            let Some(returned) =
                serve_external_exchange(router, exchange, call, &deadline, shutdown).await?
            else {
                return Ok(ConnectionEnd::Closed);
            };
            connection = returned;
            continue;
        }
        if let Some(input) = exchange.adopted.take() {
            let output = router.execute_adoption(input, &deadline).await;
            connection = exchange.reply_adoption(output, &deadline).await?;
            continue;
        }
        #[cfg(feature = "remote")]
        if let Some(call) = exchange.take_owner_call() {
            let result = crate::remote::control::execute(router, call, &deadline).await;
            connection = exchange.reply_owner(result, &deadline).await?;
            continue;
        }
        let call = exchange.take_call();
        // Taken now, so no branch keeps it for the connection's life.
        let sign_in = exchange.sign_in.take();
        if let Ok(RoutedCall::Deferred { admitted, .. }) = &call
            && admitted.selections.as_ref().is_some_and(|s| s.mail_follow)
        {
            let HostedInput::Operation(se_core::ops::AnyOp::MessageList(input)) = &admitted.input
            else {
                return Err(SeError::invalid("mail follow", "message list input"));
            };
            let input = input.clone();
            let selections = admitted.selections.clone();
            super::mail_follow::serve(router, exchange, input, selections, shutdown).await?;
            return Ok(ConnectionEnd::Closed);
        }
        let output = match call {
            Ok(call)
                if matches!(&call, RoutedCall::Deferred { admitted, .. }
                    if matches!(&admitted.input, HostedInput::Operation(se_core::ops::AnyOp::RemoteWatch(_)))) =>
            {
                // Unlike writes, a watch owns no commit. Retire its in-flight
                // page as soon as this CLI disconnects, preserving consumed
                // cursors and leaving the target agent untouched.
                tokio::select! {biased;
                    closed = exchange.wait_for_peer_close() => {
                        closed?;
                        return Ok(ConnectionEnd::Closed);
                    }
                    output = router.execute_call(call, &deadline) => output,
                }
            }
            Ok(call) => {
                crate::launch_sign_in::scope(sign_in, router.execute_call(call, &deadline)).await
            }
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
async fn serve_external_exchange(
    router: &HostedRouter,
    exchange: AdmittedExchange,
    call: super::admission::external::ExternalCall,
    deadline: &Deadline,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<Option<HostedConnection>> {
    let active_binding = Arc::clone(&exchange.connection.grant.external_active);
    let result = match call {
        // Mutating Owner lifecycle calls must survive an Owner client disconnect
        // once admitted so lease registration + bridge delivery (or rollback)
        // always runs to completion on the host.
        super::admission::external::ExternalCall::Approve { .. }
        | super::admission::external::ExternalCall::Revoke { .. } => {
            let task_router = router.clone();
            let task_deadline = deadline.clone();
            let task_binding = Arc::clone(&active_binding);
            let mut task_shutdown = shutdown.clone();
            let handle = tokio::spawn(async move {
                crate::external::dispatch::execute(
                    &task_router,
                    call,
                    &task_binding,
                    &task_deadline,
                    &mut task_shutdown,
                )
                .await
            });
            tokio::select! {
                biased;
                closed = exchange.wait_for_peer_close() => {
                    closed?;
                    return Ok(None);
                }
                joined = super::pool::within(deadline, handle) => {
                    joined?.map_err(|e| {
                        se_core::scope::unreadable("external lifecycle task", &e.to_string())
                    })?
                }
            }
        }
        other => tokio::select! {
            biased;
            closed = exchange.wait_for_peer_close() => {
                closed?;
                return Ok(None);
            }
            result = crate::external::dispatch::execute(
                router,
                other,
                &active_binding,
                deadline,
                shutdown,
            ) => result,
        },
    };
    let reply_deadline = options(CALL_TIMEOUT)?;
    match result {
        Ok(crate::external::dispatch::DispatchOutput {
            output,
            bridge_witness: Some(witness),
        }) => {
            let _work = router.execution.mail_waits.client_work()?;
            let connection = exchange.reply_external(Ok(output), &reply_deadline).await?;
            crate::external::dispatch::hold_approved_bridge(
                router,
                connection,
                witness,
                &active_binding,
                shutdown,
            )
            .await?;
            Ok(None)
        }
        Ok(crate::external::dispatch::DispatchOutput {
            output,
            bridge_witness: None,
        }) => exchange
            .reply_external(Ok(output), &reply_deadline)
            .await
            .map(Some),
        Err(error) => exchange
            .reply_external(Err(error), &reply_deadline)
            .await
            .map(Some),
    }
}

// The authenticated caller's clock already includes connection/authentication.
// Starting another thirty seconds here loses the stop reply at the client.
fn shutdown_bound(stop: Option<&AuthorizedStop>) -> Result<Deadline> {
    let timeout = match stop {
        Some(stop) => {
            let now = u64::try_from(super::start::now_unix_micros()?)
                .map_err(|_| SeError::invalid("stop clock", "positive Unix microseconds"))?;
            std::time::Duration::from_micros(
                stop.request()?.deadline_at.get().saturating_sub(now).max(1),
            )
        }
        None => CALL_TIMEOUT,
    };
    options(timeout)
}

pub(crate) fn options(timeout: std::time::Duration) -> Result<Deadline> {
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
pub(crate) async fn idle_expiry(activity: &mut watch::Receiver<u32>) {
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
    pub fn configuration(&self) -> Option<&se_config::config_policy::ConfigFile> {
        self.configuration.as_ref()
    }
}
