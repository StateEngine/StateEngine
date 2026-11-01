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
}
#[allow(
    clippy::large_enum_variant,
    reason = "One bounded supervisor stack value avoids a heap allocation on every accept."
)]
enum Event {
    Accepted(Result<crate::AcceptedIpcStream>),
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
        let (shutdown, cancelled) = watch::channel(None);
        let mut tasks = JoinSet::new();
        let mut accept_backoff = std::time::Duration::from_millis(1);
        let mut accept_retry_at = tokio::time::Instant::now();
        let mut outcome = loop {
            match event(&mut listener, &mut tasks, accept_retry_at).await {
                Event::Accepted(Ok(stream)) => {
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
                Event::Accepted(Err(error)) => break ended(self, listener, Some(error)),
                Event::Joined(Ok(Ok(ConnectionEnd::Stop(stop)))) => {
                    let mut exit = ended(self, listener, None);
                    exit.stop = Some(stop);
                    break exit;
                }
                Event::Joined(Ok(Ok(ConnectionEnd::Closed | ConnectionEnd::Cancelled))) => (),
                Event::Joined(Ok(Err(error))) => {
                    self.failed_connection(error);
                }
                Event::Joined(Err(error)) => {
                    break ended(
                        self,
                        listener,
                        Some(
                            se_core::scope::unreadable("host connection task", &error.to_string())
                                .with_cause(error),
                        ),
                    );
                }
            }
        };
        outcome.runtime.fenced.store(true, Ordering::Release);
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
    tasks: &mut JoinSet<Result<ConnectionEnd>>,
    retry_at: tokio::time::Instant,
) -> Event {
    let mut accepting = pin!(async {
        tokio::time::sleep_until(retry_at).await;
        listener.accept(Arc::new(AtomicBool::new(false))).await
    });
    poll_fn(|cx| {
        if !tasks.is_empty()
            && let Poll::Ready(Some(joined)) = tasks.poll_join_next(cx)
        {
            return Poll::Ready(Event::Joined(joined));
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
