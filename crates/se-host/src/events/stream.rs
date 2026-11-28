//! Long-lived cursor-resumable push event stream over local IPC.
//!
//! Acquires `mail_waits.client_work()?`, never returns to 300s `read_call_idle`,
//! bounds per-subscriber memory via a fixed-capacity queue (emitting `{ kind:
//! "lagged", missed_through_cursor }` and closing on overflow), emits periodic
//! `{ kind: "heartbeat", head_cursor }` frames, fences queued frames and
//! in-progress writes on revocation/shutdown, and terminates cleanly on peer
//! EOF, session/lease revocation or expiry, or host shutdown.
use super::{
    ControlFrame, DEFAULT_HEARTBEAT_SECS, EVENT_STREAM_SCHEMA, EventPushFrame,
    MAX_SUBSCRIBER_QUEUE, SubscribeFrame,
    admit::{AdmittedSubscribe, SubscribePrincipal},
    scan,
};
use crate::{
    OperationOutput,
    client::lease::Deadline,
    ipc::StreamWriteOutcome,
    runtime::{AdmittedExchange, HostedRouter, MailRecipient},
};
use se_types::{Result, SeError};
use std::{pin::pin, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, watch};

enum ProducerEvent {
    Frame(EventPushFrame, String),
    Advance(String),
}

pub(crate) async fn serve(
    router: &HostedRouter,
    mut exchange: AdmittedExchange,
    sub: AdmittedSubscribe,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<()> {
    serve_with_config(
        router,
        &mut exchange,
        sub,
        shutdown,
        MAX_SUBSCRIBER_QUEUE,
        Duration::from_secs(DEFAULT_HEARTBEAT_SECS),
    )
    .await
}

pub(crate) async fn serve_with_config(
    router: &HostedRouter,
    exchange: &mut AdmittedExchange,
    sub: AdmittedSubscribe,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    queue_capacity: usize,
    heartbeat_interval: Duration,
) -> Result<()> {
    let _work = router.execution.mail_waits.client_work()?;
    let session_wait = register_session_wait(router, &sub)?;
    let mut commits = router.execution.mail_waits.commits.subscribe();
    commits.borrow_and_update();

    let sub = Arc::new(sub);
    let (start_seq, initial_cursor) = match scan::resolve_start_cursor(router, &sub).await {
        Ok(pair) => pair,
        Err(err) => {
            send_error(exchange, err, sub.max_batch_bytes, shutdown).await?;
            return Ok(());
        }
    };

    let cap = queue_capacity.max(1);
    let (tx, mut rx) = mpsc::channel::<ProducerEvent>(cap);
    let (fatal_tx, mut fatal_rx) = oneshot::channel::<SeError>();
    let (lagged_tx, mut lagged_rx) = oneshot::channel::<String>();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let cancel_signal = session_wait.as_ref().map(|w| Arc::clone(&w.signal));
    let producer = spawn_producer(
        router.clone(),
        Arc::clone(&sub),
        start_seq,
        cap.min(MAX_SUBSCRIBER_QUEUE),
        commits,
        cancel_signal.clone(),
        shutdown.clone(),
        stop_rx,
        tx,
        fatal_tx,
        lagged_tx,
    );

    let result = pump_stream(
        router,
        exchange,
        &sub,
        initial_cursor,
        heartbeat_interval,
        cancel_signal,
        shutdown,
        &mut rx,
        &mut fatal_rx,
        &mut lagged_rx,
    )
    .await;

    let _ = stop_tx.send(());
    let join_res = producer.await;
    drop(session_wait);
    result?;
    join_res
        .map_err(|err| se_core::scope::unreadable("event stream producer", &err.to_string()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn pump_stream(
    router: &HostedRouter,
    exchange: &mut AdmittedExchange,
    sub: &AdmittedSubscribe,
    mut head_cursor: String,
    heartbeat_interval: Duration,
    cancel_signal: Option<Arc<crate::http::mail::Signal>>,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    rx: &mut mpsc::Receiver<ProducerEvent>,
    fatal_rx: &mut oneshot::Receiver<SeError>,
    lagged_rx: &mut oneshot::Receiver<String>,
) -> Result<()> {
    if is_cancelled(&cancel_signal) {
        send_error(exchange, revoked_error(), sub.max_batch_bytes, shutdown).await?;
        return Ok(());
    }
    if sub.after_cursor.is_none() {
        let init_hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
            head_cursor: head_cursor.clone(),
        });
        if !send_cancellable(exchange, sub, &cancel_signal, shutdown, &init_hb, false).await? {
            return Ok(());
        }
    }

    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;

    let mut fatal_rx = Some(fatal_rx);
    let mut lagged_rx = Some(lagged_rx);
    loop {
        if is_cancelled(&cancel_signal) {
            send_error(exchange, revoked_error(), sub.max_batch_bytes, shutdown).await?;
            return Ok(());
        }
        let wait_fatal = wait_optional(&mut fatal_rx);
        let wait_lagged = wait_optional(&mut lagged_rx);
        let wait_cancel = wait_for_cancel(&cancel_signal);
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            closed = exchange.wait_for_peer_close() => {
                closed?;
                return Ok(());
            }
            fatal = wait_fatal => match fatal {
                Ok(err) => {
                    send_error(exchange, err, sub.max_batch_bytes, shutdown).await?;
                    return Ok(());
                }
                Err(_) => {
                    fatal_rx = None;
                }
            },
            _ = wait_cancel => {
                send_error(exchange, revoked_error(), sub.max_batch_bytes, shutdown).await?;
                return Ok(());
            }
            lagged = wait_lagged => match lagged {
                Ok(missed_through_cursor) => {
                    let frame = SubscribeFrame::Control(ControlFrame::Lagged {
                        missed_through_cursor,
                    });
                    let _ = send_cancellable(exchange, sub, &cancel_signal, shutdown, &frame, true).await?;
                    return Ok(());
                }
                Err(_) => {
                    lagged_rx = None;
                }
            },
            item = rx.recv() => {
                if !handle_producer_item(
                    exchange,
                    sub,
                    &cancel_signal,
                    shutdown,
                    &mut head_cursor,
                    &mut heartbeat,
                    &mut fatal_rx,
                    item,
                )
                .await?
                {
                    return Ok(());
                }
            }
            _ = heartbeat.tick() => {
                if !handle_heartbeat_tick(
                    router,
                    exchange,
                    sub,
                    &cancel_signal,
                    shutdown,
                    &head_cursor,
                )
                .await?
                {
                    return Ok(());
                }
            }
        }
    }
}

async fn wait_optional<T>(
    rx: &mut Option<&mut oneshot::Receiver<T>>,
) -> std::result::Result<T, oneshot::error::RecvError> {
    match rx {
        Some(rx) => rx.await,
        None => std::future::pending().await,
    }
}

async fn wait_for_cancel(signal: &Option<Arc<crate::http::mail::Signal>>) {
    let Some(sig) = signal else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if sig.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        sig.changed.notified().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_producer_item(
    exchange: &mut AdmittedExchange,
    sub: &AdmittedSubscribe,
    cancel_signal: &Option<Arc<crate::http::mail::Signal>>,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    head_cursor: &mut String,
    heartbeat: &mut tokio::time::Interval,
    fatal_rx: &mut Option<&mut oneshot::Receiver<SeError>>,
    item: Option<ProducerEvent>,
) -> Result<bool> {
    match item {
        Some(ProducerEvent::Frame(frame, cur)) => {
            if is_cancelled(cancel_signal) {
                send_error(exchange, revoked_error(), sub.max_batch_bytes, shutdown).await?;
                return Ok(false);
            }
            let wrapped = SubscribeFrame::Event(frame);
            if !send_cancellable(exchange, sub, cancel_signal, shutdown, &wrapped, false).await? {
                return Ok(false);
            }
            *head_cursor = cur;
            heartbeat.reset();
            Ok(true)
        }
        Some(ProducerEvent::Advance(cur)) => {
            *head_cursor = cur;
            Ok(true)
        }
        None => {
            if let Some(rx) = fatal_rx.take()
                && let Ok(err) = rx.try_recv()
            {
                send_error(exchange, err, sub.max_batch_bytes, shutdown).await?;
            }
            Ok(false)
        }
    }
}

async fn handle_heartbeat_tick(
    router: &HostedRouter,
    exchange: &mut AdmittedExchange,
    sub: &AdmittedSubscribe,
    cancel_signal: &Option<Arc<crate::http::mail::Signal>>,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    head_cursor: &str,
) -> Result<bool> {
    if is_cancelled(cancel_signal) {
        send_error(exchange, revoked_error(), sub.max_batch_bytes, shutdown).await?;
        return Ok(false);
    }
    if let Err(err) = scan::verify_live_authority(router, sub).await {
        send_error(exchange, err, sub.max_batch_bytes, shutdown).await?;
        return Ok(false);
    }
    let hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
        head_cursor: head_cursor.to_owned(),
    });
    send_cancellable(exchange, sub, cancel_signal, shutdown, &hb, false).await
}

fn register_session_wait(
    router: &HostedRouter,
    sub: &AdmittedSubscribe,
) -> Result<Option<crate::http::mail::SubscriptionWait>> {
    match &sub.principal {
        SubscribePrincipal::Owner { .. } => Ok(None),
        SubscribePrincipal::Session {
            project,
            agent,
            session,
            credential,
            ..
        } => router
            .execution
            .mail_waits
            .register_subscription(
                session.clone(),
                MailRecipient {
                    project: project.clone(),
                    agent: agent.clone(),
                },
                *credential,
            )
            .map(Some),
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_producer(
    router: HostedRouter,
    sub: Arc<AdmittedSubscribe>,
    start_seq: u64,
    max_scan_items: usize,
    mut commits: watch::Receiver<u64>,
    cancel_signal: Option<Arc<crate::http::mail::Signal>>,
    mut shutdown: watch::Receiver<Option<Deadline>>,
    mut stop_rx: oneshot::Receiver<()>,
    tx: mpsc::Sender<ProducerEvent>,
    fatal_tx: oneshot::Sender<SeError>,
    lagged_tx: oneshot::Sender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_seq = start_seq;
        let mut drain = sub.after_cursor.is_some();
        loop {
            if is_cancelled(&cancel_signal) {
                let _ = fatal_tx.send(revoked_error());
                return;
            }
            if drain {
                commits.borrow_and_update();
                match scan::scan_events(&router, &sub, last_seq, max_scan_items).await {
                    Ok(outcome) => {
                        let had_frames = !outcome.frames.is_empty();
                        for frame in outcome.frames {
                            if is_cancelled(&cancel_signal) {
                                let _ = fatal_tx.send(revoked_error());
                                return;
                            }
                            let cur = frame.cursor.clone();
                            match tx.try_send(ProducerEvent::Frame(frame, cur)) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    let _ = lagged_tx.send(outcome.missed_cursor);
                                    return;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => return,
                            }
                        }
                        if !had_frames && outcome.next_seq > last_seq {
                            let _ = tx.try_send(ProducerEvent::Advance(outcome.safe_cursor));
                        }
                        last_seq = outcome.next_seq;
                        drain = outcome.has_more;
                        if drain {
                            continue;
                        }
                    }
                    Err(err) => {
                        let _ = fatal_tx.send(err);
                        return;
                    }
                }
            }
            tokio::select! {
                biased;
                _ = &mut stop_rx => return,
                _ = shutdown.changed() => return,
                _ = wait_for_cancel(&cancel_signal) => {
                    let _ = fatal_tx.send(revoked_error());
                    return;
                }
                changed = commits.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    drain = true;
                }
            }
        }
    })
}

fn is_cancelled(signal: &Option<Arc<crate::http::mail::Signal>>) -> bool {
    signal
        .as_ref()
        .is_some_and(|sig| sig.cancelled.load(std::sync::atomic::Ordering::Acquire))
}

fn revoked_error() -> SeError {
    SeError::new(se_types::Detail::CapabilityInvalid(
        se_types::details::CapabilityInvalid {
            subject: "events.subscribe".into(),
            reason: "this seat's active session was revoked, replaced, or disconnected".into(),
            next_step: "reconnect with an active session credential".into(),
        },
    ))
}

fn oversize_frame_error(limit_bytes: u32, exact_bytes: usize) -> SeError {
    SeError::new(se_types::Detail::InputTooLarge(
        se_types::details::InputTooLarge {
            field: "events.subscribe frame".into(),
            limit_bytes: u64::from(limit_bytes),
            got_bytes: exact_bytes as u64,
        },
    ))
}

async fn send_cancellable(
    exchange: &mut AdmittedExchange,
    sub: &AdmittedSubscribe,
    cancel_signal: &Option<Arc<crate::http::mail::Signal>>,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    frame: &SubscribeFrame,
    terminal: bool,
) -> Result<bool> {
    let value = serde_json::to_value(frame)
        .map_err(|e| se_core::scope::unreadable("event stream frame", &e.to_string()))?;
    let output = OperationOutput {
        schema: EVENT_STREAM_SCHEMA.to_owned(),
        value,
        window: None,
    };
    let mut shutdown_watch = shutdown.clone();
    let cancel = pin!(async {
        tokio::select! {
            biased;
            _ = shutdown_watch.changed() => {}
            _ = wait_for_cancel(cancel_signal) => {}
        }
    });
    match exchange
        .reply_stream_part_cancellable(Ok(output), sub.max_batch_bytes as usize, terminal, cancel)
        .await?
    {
        StreamWriteOutcome::Sent => Ok(true),
        StreamWriteOutcome::InterruptedPartial => Ok(false),
        StreamWriteOutcome::CancelledBeforeWrite => {
            if is_cancelled(cancel_signal) {
                send_error(exchange, revoked_error(), sub.max_batch_bytes, shutdown).await?;
            }
            Ok(false)
        }
        StreamWriteOutcome::Oversize { exact_bytes } => {
            send_error(
                exchange,
                oversize_frame_error(sub.max_batch_bytes, exact_bytes),
                sub.max_batch_bytes,
                shutdown,
            )
            .await?;
            Ok(false)
        }
    }
}

async fn send_error(
    exchange: &mut AdmittedExchange,
    error: SeError,
    max_batch_bytes: u32,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<()> {
    let mut shutdown_watch = shutdown.clone();
    let cancel = pin!(async {
        let _ = shutdown_watch.changed().await;
    });
    let _ = exchange
        .reply_stream_part_cancellable(Err(error), max_batch_bytes as usize, true, cancel)
        .await?;
    Ok(())
}
