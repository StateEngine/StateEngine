//! Long-lived cursor-resumable push event stream over local IPC.
//!
//! Acquires `mail_waits.client_work()?`, never returns to 300s `read_call_idle`,
//! bounds per-subscriber memory via a fixed-capacity queue (emitting `{ kind:
//! "lagged", missed_through_cursor }` and closing on overflow), emits periodic
//! `{ kind: "heartbeat", head_cursor }` frames, fences queued frames on
//! revocation, and terminates cleanly on peer EOF, session/lease revocation or
//! expiry, or host shutdown.
use super::{
    ControlFrame, DEFAULT_HEARTBEAT_SECS, EVENT_STREAM_SCHEMA, EventPushFrame,
    MAX_SUBSCRIBER_QUEUE, SubscribeFrame,
    admit::{AdmittedSubscribe, SubscribePrincipal},
    scan,
};
use crate::{
    OperationOutput,
    client::lease::Deadline,
    runtime::{AdmittedExchange, HostedRouter, MailRecipient},
};
use se_types::{Result, SeError};
use std::{sync::Arc, time::Duration};
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
    let (start_seq, initial_head_cursor) = match scan::resolve_start_cursor(router, &sub).await {
        Ok(pair) => pair,
        Err(err) => {
            send_error(exchange, err).await?;
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
        initial_head_cursor,
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
        send_error(exchange, revoked_error()).await?;
        return Ok(());
    }
    if sub.after_cursor.is_none() {
        let init_hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
            head_cursor: head_cursor.clone(),
        });
        send_frame(exchange, &init_hb, sub.max_batch_bytes, false).await?;
    }

    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;

    let mut fatal_rx = Some(fatal_rx);
    let mut lagged_rx = Some(lagged_rx);
    loop {
        if is_cancelled(&cancel_signal) {
            send_error(exchange, revoked_error()).await?;
            return Ok(());
        }
        let wait_fatal = wait_optional(&mut fatal_rx);
        let wait_lagged = wait_optional(&mut lagged_rx);
        let wait_cancel = async {
            match &cancel_signal {
                Some(sig) => sig.changed.notified().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            closed = exchange.wait_for_peer_close() => {
                closed?;
                return Ok(());
            }
            fatal = wait_fatal => match fatal {
                Ok(err) => {
                    send_error(exchange, err).await?;
                    return Ok(());
                }
                Err(_) => {
                    fatal_rx = None;
                }
            },
            _ = wait_cancel => {
                if is_cancelled(&cancel_signal) {
                    send_error(exchange, revoked_error()).await?;
                    return Ok(());
                }
            }
            lagged = wait_lagged => match lagged {
                Ok(missed_through_cursor) => {
                    if is_cancelled(&cancel_signal) {
                        send_error(exchange, revoked_error()).await?;
                        return Ok(());
                    }
                    let frame = SubscribeFrame::Control(ControlFrame::Lagged {
                        missed_through_cursor,
                    });
                    send_frame(exchange, &frame, sub.max_batch_bytes, true).await?;
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
                    &mut head_cursor,
                    &mut heartbeat,
                    &mut fatal_rx,
                    item,
                ).await? {
                    return Ok(());
                }
            }
            _ = heartbeat.tick() => {
                if !handle_heartbeat_tick(
                    router,
                    exchange,
                    sub,
                    &cancel_signal,
                    &head_cursor,
                ).await? {
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

async fn handle_producer_item(
    exchange: &mut AdmittedExchange,
    sub: &AdmittedSubscribe,
    cancel_signal: &Option<Arc<crate::http::mail::Signal>>,
    head_cursor: &mut String,
    heartbeat: &mut tokio::time::Interval,
    fatal_rx: &mut Option<&mut oneshot::Receiver<SeError>>,
    item: Option<ProducerEvent>,
) -> Result<bool> {
    match item {
        Some(ProducerEvent::Frame(frame, cur)) => {
            if is_cancelled(cancel_signal) {
                send_error(exchange, revoked_error()).await?;
                return Ok(false);
            }
            let wrapped = SubscribeFrame::Event(frame);
            match send_frame(exchange, &wrapped, sub.max_batch_bytes, false).await {
                Ok(()) => {
                    *head_cursor = cur;
                    heartbeat.reset();
                    Ok(true)
                }
                Err(err) if is_frame_oversize(&err) => {
                    send_error(exchange, oversize_frame_error(sub.max_batch_bytes)).await?;
                    Ok(false)
                }
                Err(err) => Err(err),
            }
        }
        Some(ProducerEvent::Advance(cur)) => {
            *head_cursor = cur;
            Ok(true)
        }
        None => {
            if let Some(rx) = fatal_rx.take()
                && let Ok(err) = rx.try_recv()
            {
                send_error(exchange, err).await?;
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
    head_cursor: &str,
) -> Result<bool> {
    if is_cancelled(cancel_signal) {
        send_error(exchange, revoked_error()).await?;
        return Ok(false);
    }
    if let Err(err) = scan::verify_live_authority(router, sub).await {
        send_error(exchange, err).await?;
        return Ok(false);
    }
    let hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
        head_cursor: head_cursor.to_owned(),
    });
    send_frame(exchange, &hb, sub.max_batch_bytes, false).await?;
    Ok(true)
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
                        if !had_frames && !outcome.has_more && outcome.next_seq > last_seq {
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
            let wait_signal = async {
                match &cancel_signal {
                    Some(sig) => sig.changed.notified().await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                biased;
                _ = &mut stop_rx => return,
                _ = shutdown.changed() => return,
                _ = wait_signal => {
                    if is_cancelled(&cancel_signal) {
                        let _ = fatal_tx.send(revoked_error());
                        return;
                    }
                    drain = true;
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

fn is_frame_oversize(err: &SeError) -> bool {
    err.code() == se_types::Code::UsageInvalidValue
}

fn oversize_frame_error(limit_bytes: u32) -> SeError {
    SeError::new(se_types::Detail::InputTooLarge(
        se_types::details::InputTooLarge {
            field: "events.subscribe frame".into(),
            limit_bytes: u64::from(limit_bytes),
            got_bytes: u64::from(limit_bytes).saturating_add(1),
        },
    ))
}

async fn send_frame(
    exchange: &mut AdmittedExchange,
    frame: &SubscribeFrame,
    max_batch_bytes: u32,
    terminal: bool,
) -> Result<()> {
    let value = serde_json::to_value(frame)
        .map_err(|e| se_core::scope::unreadable("event stream frame", &e.to_string()))?;
    let output = OperationOutput {
        schema: EVENT_STREAM_SCHEMA.to_owned(),
        value,
        window: None,
    };
    exchange
        .reply_stream_part(Ok(output), max_batch_bytes as usize, terminal)
        .await
}

async fn send_error(exchange: &mut AdmittedExchange, error: SeError) -> Result<()> {
    exchange
        .reply_stream_part(Err(error), crate::client::wire::MAX_FRAME_BYTES, true)
        .await
}
