//! Long-lived cursor-resumable push event stream over local IPC.
//!
//! Acquires `mail_waits.client_work()?`, never returns to 300s `read_call_idle`,
//! bounds per-subscriber memory via a fixed-capacity channel with async
//! backpressure (so backlog catch-up completes cleanly on one connection), emits
//! periodic `{ kind: "heartbeat", head_cursor }` frames, fences queued frames
//! and in-progress writes on revocation/shutdown, and terminates cleanly on peer
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

struct PumpContext<'a> {
    router: &'a HostedRouter,
    sub: &'a AdmittedSubscribe,
    cancel_signal: Option<Arc<crate::http::mail::SubscriptionSignal>>,
    heartbeat_interval: Duration,
}

struct ProducerConfig {
    router: HostedRouter,
    sub: Arc<AdmittedSubscribe>,
    start_seq: u64,
    max_scan_items: usize,
    commits: watch::Receiver<u64>,
    cancel_signal: Option<Arc<crate::http::mail::SubscriptionSignal>>,
    shutdown: watch::Receiver<Option<Deadline>>,
    stop_rx: oneshot::Receiver<()>,
    tx: mpsc::Sender<ProducerEvent>,
    fatal_tx: oneshot::Sender<SeError>,
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
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let cancel_signal = session_wait.as_ref().map(|w| Arc::clone(&w.signal));
    let producer = spawn_producer(ProducerConfig {
        router: router.clone(),
        sub: Arc::clone(&sub),
        start_seq,
        max_scan_items: cap.min(MAX_SUBSCRIBER_QUEUE),
        commits,
        cancel_signal: cancel_signal.clone(),
        shutdown: shutdown.clone(),
        stop_rx,
        tx,
        fatal_tx,
    });

    let pump = PumpContext {
        router,
        sub: &sub,
        cancel_signal,
        heartbeat_interval,
    };
    let result = pump_stream(
        &pump,
        exchange,
        initial_cursor,
        shutdown,
        &mut rx,
        &mut fatal_rx,
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

async fn pump_stream(
    pump: &PumpContext<'_>,
    exchange: &mut AdmittedExchange,
    mut head_cursor: String,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    rx: &mut mpsc::Receiver<ProducerEvent>,
    fatal_rx: &mut oneshot::Receiver<SeError>,
) -> Result<()> {
    if is_cancelled(&pump.cancel_signal) {
        send_error(
            exchange,
            revoked_error(),
            pump.sub.max_batch_bytes,
            shutdown,
        )
        .await?;
        return Ok(());
    }
    if pump.sub.after_cursor.is_none() {
        let init_hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
            head_cursor: head_cursor.clone(),
        });
        if !send_cancellable(pump, exchange, shutdown, &init_hb, false).await? {
            return Ok(());
        }
    }

    let mut heartbeat = tokio::time::interval(pump.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;

    let mut fatal_rx = Some(fatal_rx);
    loop {
        if is_cancelled(&pump.cancel_signal) {
            send_error(
                exchange,
                revoked_error(),
                pump.sub.max_batch_bytes,
                shutdown,
            )
            .await?;
            return Ok(());
        }
        let wait_fatal = wait_optional(&mut fatal_rx);
        let wait_cancel = wait_for_cancel(&pump.cancel_signal);
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            closed = exchange.wait_for_peer_close() => {
                closed?;
                return Ok(());
            }
            fatal = wait_fatal => match fatal {
                Ok(err) => {
                    send_error(exchange, err, pump.sub.max_batch_bytes, shutdown).await?;
                    return Ok(());
                }
                Err(_) => {
                    fatal_rx = None;
                }
            },
            _ = wait_cancel => {
                send_error(exchange, revoked_error(), pump.sub.max_batch_bytes, shutdown).await?;
                return Ok(());
            }
            item = rx.recv() => {
                if !handle_producer_item(
                    pump,
                    exchange,
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
                if !handle_heartbeat_tick(pump, exchange, shutdown, &head_cursor).await? {
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

async fn wait_for_cancel(signal: &Option<Arc<crate::http::mail::SubscriptionSignal>>) {
    let Some(sig) = signal else {
        std::future::pending::<()>().await;
        return;
    };
    let mut rx = sig.subscribe();
    let _ = rx.wait_for(|&cancelled| cancelled).await;
}

async fn handle_producer_item(
    pump: &PumpContext<'_>,
    exchange: &mut AdmittedExchange,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    head_cursor: &mut String,
    heartbeat: &mut tokio::time::Interval,
    fatal_rx: &mut Option<&mut oneshot::Receiver<SeError>>,
    item: Option<ProducerEvent>,
) -> Result<bool> {
    match item {
        Some(ProducerEvent::Frame(frame, cur)) => {
            if is_cancelled(&pump.cancel_signal) {
                send_error(
                    exchange,
                    revoked_error(),
                    pump.sub.max_batch_bytes,
                    shutdown,
                )
                .await?;
                return Ok(false);
            }
            let wrapped = SubscribeFrame::Event(frame);
            if !send_cancellable(pump, exchange, shutdown, &wrapped, false).await? {
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
                send_error(exchange, err, pump.sub.max_batch_bytes, shutdown).await?;
            }
            Ok(false)
        }
    }
}

async fn handle_heartbeat_tick(
    pump: &PumpContext<'_>,
    exchange: &mut AdmittedExchange,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    head_cursor: &str,
) -> Result<bool> {
    if is_cancelled(&pump.cancel_signal) {
        send_error(
            exchange,
            revoked_error(),
            pump.sub.max_batch_bytes,
            shutdown,
        )
        .await?;
        return Ok(false);
    }
    if let Err(err) = scan::verify_live_authority(pump.router, pump.sub).await {
        send_error(exchange, err, pump.sub.max_batch_bytes, shutdown).await?;
        return Ok(false);
    }
    let hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
        head_cursor: head_cursor.to_owned(),
    });
    send_cancellable(pump, exchange, shutdown, &hb, false).await
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

fn spawn_producer(cfg: ProducerConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let ProducerConfig {
            router,
            sub,
            start_seq,
            max_scan_items,
            mut commits,
            cancel_signal,
            mut shutdown,
            mut stop_rx,
            tx,
            fatal_tx,
        } = cfg;
        let mut last_seq = start_seq;
        let mut drain = sub.after_cursor.is_some();
        loop {
            if is_cancelled(&cancel_signal) {
                let _ = fatal_tx.send(revoked_error());
                return;
            }
            if drain {
                commits.borrow_and_update();
                match scan::scan_events(&router, Arc::clone(&sub), last_seq, max_scan_items).await {
                    Ok(outcome) => {
                        let had_frames = !outcome.frames.is_empty();
                        for frame in outcome.frames {
                            let cur = frame.cursor.clone();
                            tokio::select! {
                                biased;
                                _ = &mut stop_rx => return,
                                _ = shutdown.changed() => return,
                                _ = wait_for_cancel(&cancel_signal) => {
                                    let _ = fatal_tx.send(revoked_error());
                                    return;
                                }
                                res = tx.send(ProducerEvent::Frame(frame, cur)) => {
                                    if res.is_err() {
                                        return;
                                    }
                                }
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

fn is_cancelled(signal: &Option<Arc<crate::http::mail::SubscriptionSignal>>) -> bool {
    signal.as_ref().is_some_and(|sig| sig.is_cancelled())
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
    pump: &PumpContext<'_>,
    exchange: &mut AdmittedExchange,
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
            _ = wait_for_cancel(&pump.cancel_signal) => {}
        }
    });
    match exchange
        .reply_stream_part_cancellable(
            Ok(output),
            pump.sub.max_batch_bytes as usize,
            terminal,
            cancel,
        )
        .await?
    {
        StreamWriteOutcome::Sent => Ok(true),
        StreamWriteOutcome::InterruptedPartial => Ok(false),
        StreamWriteOutcome::CancelledBeforeWrite => {
            if is_cancelled(&pump.cancel_signal) {
                send_error(
                    exchange,
                    revoked_error(),
                    pump.sub.max_batch_bytes,
                    shutdown,
                )
                .await?;
            }
            Ok(false)
        }
        StreamWriteOutcome::Oversize { exact_bytes } => {
            send_error(
                exchange,
                oversize_frame_error(pump.sub.max_batch_bytes, exact_bytes),
                pump.sub.max_batch_bytes,
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
    let original_code = error.code();
    let mut shutdown_watch = shutdown.clone();
    let cancel = pin!(async {
        let _ = shutdown_watch.changed().await;
    });
    match exchange
        .reply_stream_part_cancellable(Err(error), max_batch_bytes as usize, true, cancel)
        .await?
    {
        StreamWriteOutcome::Sent
        | StreamWriteOutcome::CancelledBeforeWrite
        | StreamWriteOutcome::InterruptedPartial => Ok(()),
        StreamWriteOutcome::Oversize { exact_bytes } => {
            let fallback = SeError::new(se_types::Detail::InputTooLarge(
                se_types::details::InputTooLarge {
                    field: format!(
                        "events.subscribe terminal error ({})",
                        original_code.as_str()
                    ),
                    limit_bytes: u64::from(max_batch_bytes),
                    got_bytes: exact_bytes as u64,
                },
            ));
            let mut shutdown_watch = shutdown.clone();
            let cancel = pin!(async {
                let _ = shutdown_watch.changed().await;
            });
            match exchange
                .reply_stream_part_cancellable(
                    Err(fallback),
                    max_batch_bytes as usize,
                    true,
                    cancel,
                )
                .await?
            {
                StreamWriteOutcome::Sent
                | StreamWriteOutcome::CancelledBeforeWrite
                | StreamWriteOutcome::InterruptedPartial => Ok(()),
                StreamWriteOutcome::Oversize { exact_bytes } => Err(SeError::new(
                    se_types::Detail::InputTooLarge(se_types::details::InputTooLarge {
                        field: "events.subscribe terminal error".into(),
                        limit_bytes: u64::from(max_batch_bytes),
                        got_bytes: exact_bytes as u64,
                    }),
                )),
            }
        }
    }
}
