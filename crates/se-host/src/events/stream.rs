//! Long-lived cursor-resumable push event stream over local IPC.
//!
//! Acquires `mail_waits.client_work()?`, never returns to 300s `read_call_idle`,
//! bounds per-subscriber memory via a fixed-capacity queue (emitting `{ kind:
//! "lagged", missed_through_cursor }` and closing on overflow), emits periodic
//! `{ kind: "heartbeat", head_cursor }` frames, and terminates cleanly on peer
//! EOF, session/lease revocation or expiry, or host shutdown.
use super::{
    ControlFrame, DEFAULT_HEARTBEAT_SECS, EVENT_STREAM_SCHEMA, EventPushFrame, EventStreamKind,
    MAX_SUBSCRIBER_QUEUE, SubscribeFrame,
    admit::{AdmittedSubscribe, SubscribePrincipal},
    cursor, project,
};
use crate::{
    OperationOutput,
    client::lease::Deadline,
    runtime::{AdmittedExchange, HostedRouter, MailRecipient},
};
use se_core::store_error::store_error;
use se_store::{
    Actor, Admission, HistoryDirection, HistoryQuery, ReadScope, ReadStore, Scope, Snapshot,
    StoreInfo, StorePosition, TranscriptFilter, Visibility,
};
use se_types::{AgentId, ProjectId, Result, SeError};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, watch};

const SCAN_LIMIT: u32 = 128;
const SCAN_BYTES: u32 = 2 * 1024 * 1024;
const SCAN_DEADLINE_SECS: u64 = 5;

struct ScanOutcome {
    frames: Vec<EventPushFrame>,
    head_seq: u64,
    head_cursor: String,
    has_more: bool,
}

enum ProducerEvent {
    Frame(EventPushFrame, String),
    Fatal(SeError),
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
    let (start_seq, initial_head_cursor) = match resolve_start_cursor(router, &sub).await {
        Ok(pair) => pair,
        Err(err) => {
            send_error(exchange, err).await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::channel::<ProducerEvent>(queue_capacity.max(1));
    let (lagged_tx, mut lagged_rx) = oneshot::channel::<String>();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let cancel_signal = session_wait.as_ref().map(|w| Arc::clone(&w.signal));
    let producer = spawn_producer(
        router.clone(),
        Arc::clone(&sub),
        start_seq,
        commits,
        cancel_signal,
        shutdown.clone(),
        stop_rx,
        tx,
        lagged_tx,
    );

    let result = pump_stream(
        router,
        exchange,
        &sub,
        initial_head_cursor,
        heartbeat_interval,
        shutdown,
        &mut rx,
        &mut lagged_rx,
    )
    .await;

    let _ = stop_tx.send(());
    let _ = producer.await;
    drop(session_wait);
    result
}

#[allow(clippy::too_many_arguments)]
async fn pump_stream(
    router: &HostedRouter,
    exchange: &mut AdmittedExchange,
    sub: &AdmittedSubscribe,
    mut head_cursor: String,
    heartbeat_interval: Duration,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
    rx: &mut mpsc::Receiver<ProducerEvent>,
    lagged_rx: &mut oneshot::Receiver<String>,
) -> Result<()> {
    if sub.after_cursor.is_none() {
        let init_hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
            head_cursor: head_cursor.clone(),
        });
        send_frame(exchange, &init_hb, sub.max_batch_bytes, false).await?;
    }

    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;

    let mut lagged_rx = Some(lagged_rx);
    loop {
        let wait_lagged = async {
            match &mut lagged_rx {
                Some(rx) => rx.await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            closed = exchange.wait_for_peer_close() => {
                let _ = closed;
                return Ok(());
            }
            lagged = wait_lagged => match lagged {
                Ok(missed_through_cursor) => {
                    let frame = SubscribeFrame::Control(ControlFrame::Lagged {
                        missed_through_cursor,
                    });
                    let _ = send_frame(exchange, &frame, sub.max_batch_bytes, true).await;
                    return Ok(());
                }
                Err(_) => {
                    lagged_rx = None;
                }
            },
            item = rx.recv() => match item {
                Some(ProducerEvent::Frame(frame, cur)) => {
                    head_cursor = cur;
                    let wrapped = SubscribeFrame::Event(frame);
                    send_frame(exchange, &wrapped, sub.max_batch_bytes, false).await?;
                    heartbeat.reset();
                }
                Some(ProducerEvent::Fatal(err)) => {
                    let _ = send_error(exchange, err).await;
                    return Ok(());
                }
                None => return Ok(()),
            },
            _ = heartbeat.tick() => {
                if let Err(err) = verify_live_authority(router, sub).await {
                    let _ = send_error(exchange, err).await;
                    return Ok(());
                }
                let hb = SubscribeFrame::Control(ControlFrame::Heartbeat {
                    head_cursor: head_cursor.clone(),
                });
                send_frame(exchange, &hb, sub.max_batch_bytes, false).await?;
            }
        }
    }
}

fn register_session_wait(
    router: &HostedRouter,
    sub: &AdmittedSubscribe,
) -> Result<Option<crate::http::mail::Wait>> {
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
            .register(
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
    mut commits: watch::Receiver<u64>,
    cancel_signal: Option<Arc<crate::http::mail::Signal>>,
    mut shutdown: watch::Receiver<Option<Deadline>>,
    mut stop_rx: oneshot::Receiver<()>,
    tx: mpsc::Sender<ProducerEvent>,
    lagged_tx: oneshot::Sender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_seq = start_seq;
        let mut drain = sub.after_cursor.is_some();
        loop {
            if is_cancelled(&cancel_signal) {
                let _ = tx.try_send(ProducerEvent::Fatal(revoked_error()));
                return;
            }
            if drain {
                commits.borrow_and_update();
                match scan_events(&router, &sub, last_seq).await {
                    Ok(outcome) => {
                        for frame in outcome.frames {
                            let cur = frame.cursor.clone();
                            match tx.try_send(ProducerEvent::Frame(frame, cur)) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    let _ = lagged_tx.send(outcome.head_cursor);
                                    return;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => return,
                            }
                        }
                        last_seq = outcome.head_seq;
                        drain = outcome.has_more;
                        if drain {
                            continue;
                        }
                    }
                    Err(err) => {
                        let _ = tx.try_send(ProducerEvent::Fatal(err));
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
                        let _ = tx.try_send(ProducerEvent::Fatal(revoked_error()));
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
    SeError::invalid(
        "events.subscribe",
        "this seat's active session was revoked, replaced, or disconnected",
    )
}

async fn resolve_start_cursor(
    router: &HostedRouter,
    sub: &AdmittedSubscribe,
) -> Result<(u64, String)> {
    router.check_open()?;
    let context = router.context.clone();
    let reader = Arc::clone(&router.execution.reader);
    let after = sub.after_cursor.clone();
    let deadline = crate::runtime::serve::options(Duration::from_secs(SCAN_DEADLINE_SECS))?;
    router
        .execution
        .blocking
        .run_owned(&deadline, move || {
            let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
            let res = (|| {
                context.check_generation(&phase)?;
                let info = reader.info().map_err(|e| store_error(&e))?;
                let head_seq = info.head.as_ref().map_or(0, StorePosition::sequence);
                let start_seq = match after.as_deref() {
                    Some(raw) => cursor::decode_and_verify(raw, &info, context.generation)?,
                    None => head_seq,
                };
                let head_cursor = cursor::encode(&info, context.generation, head_seq)?;
                Ok((start_seq, head_cursor))
            })();
            crate::runtime::executor::close_read(res, phase.close())
        })
        .await
}

async fn verify_live_authority(router: &HostedRouter, sub: &AdmittedSubscribe) -> Result<()> {
    router.check_open()?;
    let SubscribePrincipal::Session {
        secret, purpose, ..
    } = &sub.principal
    else {
        return Ok(());
    };
    let context = router.context.clone();
    let secret = Arc::clone(secret);
    let purpose = *purpose;
    let deadline = crate::runtime::serve::options(Duration::from_secs(SCAN_DEADLINE_SECS))?;
    router
        .execution
        .blocking
        .run_owned(&deadline, move || {
            let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
            let res = (|| {
                context.check_generation(&phase)?;
                if purpose == crate::external::EXTERNAL_SESSION_CAPABILITY {
                    context.external_session(&phase, &secret).map(drop)
                } else {
                    context.verify_session(&phase, &secret).map(drop)
                }
            })();
            crate::runtime::executor::close_read(res, phase.close())
        })
        .await
}

enum ScanPrincipal {
    Owner(se_types::HumanId),
    Session {
        secret: Arc<se_types::Secret>,
        purpose: &'static str,
        project: ProjectId,
        agent: AgentId,
        session: se_types::SessionId,
    },
}

async fn scan_events(
    router: &HostedRouter,
    sub: &AdmittedSubscribe,
    after_seq: u64,
) -> Result<ScanOutcome> {
    router.check_open()?;
    let context = router.context.clone();
    let reader = Arc::clone(&router.execution.reader);
    let project_filter = sub.project_filter.clone();
    let agent_filter = sub.agent_filter.clone();
    let filter = sub.filter.clone();
    let principal = match &sub.principal {
        SubscribePrincipal::Owner { human } => ScanPrincipal::Owner(human.clone()),
        SubscribePrincipal::Session {
            secret,
            purpose,
            project,
            agent,
            session,
            ..
        } => ScanPrincipal::Session {
            secret: Arc::clone(secret),
            purpose,
            project: project.clone(),
            agent: agent.clone(),
            session: session.clone(),
        },
    };
    let deadline = crate::runtime::serve::options(Duration::from_secs(SCAN_DEADLINE_SECS))?;
    router
        .execution
        .blocking
        .run_owned(&deadline, move || {
            scan_events_blocking(
                &context,
                &reader,
                &principal,
                project_filter.as_ref(),
                agent_filter.as_ref(),
                filter.as_deref(),
                after_seq,
            )
        })
        .await
}

fn scan_events_blocking(
    context: &crate::runtime::admission::AdmissionContext,
    reader: &se_store::SqliteReader,
    principal: &ScanPrincipal,
    project_filter: Option<&ProjectId>,
    agent_filter: Option<&AgentId>,
    filter: Option<&[EventStreamKind]>,
    after_seq: u64,
) -> Result<ScanOutcome> {
    let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
    if let Err(err) = context.check_generation(&phase) {
        return crate::runtime::executor::close_read(Err(err), phase.close());
    }
    let info = match reader.info().map_err(|e| store_error(&e)) {
        Ok(info) => info,
        Err(err) => return crate::runtime::executor::close_read(Err(err), phase.close()),
    };
    if let ScanPrincipal::Session {
        secret, purpose, ..
    } = principal
    {
        let auth = if *purpose == crate::external::EXTERNAL_SESSION_CAPABILITY {
            context.external_session(&phase, secret)
        } else {
            context.verify_session(&phase, secret)
        };
        if let Err(err) = auth {
            return crate::runtime::executor::close_read(Err(err), phase.close());
        }
    }

    let head_seq = info.head.as_ref().map_or(0, StorePosition::sequence);
    let head_cursor = cursor::encode(&info, context.generation, head_seq)?;
    if head_seq <= after_seq {
        return crate::runtime::executor::close_read(
            Ok(ScanOutcome {
                frames: Vec::new(),
                head_seq,
                head_cursor,
                has_more: false,
            }),
            phase.close(),
        );
    }

    let projects = resolve_projects(context, phase, principal, project_filter)?;
    let kinds = project::event_kinds_for_filter(filter);
    let since = (after_seq > 0)
        .then(|| {
            StorePosition::new_internal(info.id.clone(), info.incarnation, after_seq)
                .map_err(|e| store_error(&e))
        })
        .transpose()?;

    let mut collected: Vec<(u64, EventPushFrame)> = Vec::new();
    let mut min_truncated_seq: Option<u64> = None;
    let mut max_seen = after_seq;

    for proj in &projects {
        let scan = read_project_events(
            context,
            principal,
            proj,
            agent_filter,
            &kinds,
            filter,
            since.as_ref(),
            &info,
        )?;
        if let Some(limit_seq) = scan.truncated_at {
            min_truncated_seq = Some(min_truncated_seq.map_or(limit_seq, |cur| cur.min(limit_seq)));
        }
        for (seq, frame) in scan.items {
            max_seen = max_seen.max(seq);
            collected.push((seq, frame));
        }
    }

    collected.sort_by_key(|(seq, _)| *seq);
    if let Some(frontier) = min_truncated_seq {
        collected.retain(|(seq, _)| *seq <= frontier);
        return Ok(ScanOutcome {
            frames: collected.into_iter().map(|(_, f)| f).collect(),
            head_seq: frontier,
            head_cursor,
            has_more: true,
        });
    }
    Ok(ScanOutcome {
        frames: collected.into_iter().map(|(_, f)| f).collect(),
        head_seq: head_seq.max(max_seen),
        head_cursor,
        has_more: false,
    })
}

fn resolve_projects(
    context: &crate::runtime::admission::AdmissionContext,
    phase: se_store::ReadPhase,
    principal: &ScanPrincipal,
    project_filter: Option<&ProjectId>,
) -> Result<Vec<ProjectId>> {
    match (principal, project_filter) {
        (_, Some(project)) => {
            crate::runtime::executor::close_read(Ok(()), phase.close())?;
            Ok(vec![project.clone()])
        }
        (ScanPrincipal::Owner(human), None) => {
            let scope = ReadScope {
                admission: Admission {
                    scope: Scope::Registry,
                    actor: Actor::Human(human.clone()),
                    session: None,
                    generation: context.generation.get(),
                },
                visibility: Visibility::Owner,
            };
            let mut snap = phase.into_snapshot(scope).map_err(|e| store_error(&e))?;
            let budget = se_store::read_budget(
                None,
                256,
                SCAN_BYTES,
                Duration::from_secs(SCAN_DEADLINE_SECS),
            );
            let list = snap
                .projects(budget)
                .map_err(|e| store_error(&e))
                .map(|page| {
                    page.items()
                        .iter()
                        .filter_map(|rec| match &rec.current.body {
                            se_store::EventBody::ProjectRegistered { project, .. }
                            | se_store::EventBody::ProjectUpdated { project, .. }
                            | se_store::EventBody::ProjectMoved { project, .. } => {
                                Some(project.clone())
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                });
            crate::runtime::executor::close_read(list, snap.close())
        }
        (ScanPrincipal::Session { project, .. }, None) => {
            crate::runtime::executor::close_read(Ok(()), phase.close())?;
            Ok(vec![project.clone()])
        }
    }
}

struct ProjectScan {
    items: Vec<(u64, EventPushFrame)>,
    truncated_at: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
fn read_project_events(
    context: &crate::runtime::admission::AdmissionContext,
    principal: &ScanPrincipal,
    project_id: &ProjectId,
    agent_filter: Option<&AgentId>,
    kinds: &[se_store::EventKind],
    filter: Option<&[EventStreamKind]>,
    since: Option<&StorePosition>,
    info: &StoreInfo,
) -> Result<ProjectScan> {
    let p_phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
    let read_scope = match principal {
        ScanPrincipal::Owner(human) => ReadScope {
            admission: Admission {
                scope: Scope::Project(project_id.clone()),
                actor: Actor::Human(human.clone()),
                session: None,
                generation: context.generation.get(),
            },
            visibility: Visibility::Owner,
        },
        ScanPrincipal::Session { agent, session, .. } => ReadScope {
            admission: Admission {
                scope: Scope::Project(project_id.clone()),
                actor: Actor::Agent(agent.clone()),
                session: Some(session.clone()),
                generation: context.generation.get(),
            },
            visibility: Visibility::SelfOnly(agent.clone()),
        },
    };
    let mut snap = p_phase
        .into_snapshot(read_scope)
        .map_err(|e| store_error(&e))?;
    let query = HistoryQuery {
        agent: agent_filter.cloned(),
        session: None,
        kinds: kinds.to_vec(),
        families: Vec::new(),
        transcript: TranscriptFilter::All,
        since: since.cloned(),
        direction: HistoryDirection::OldestFirst,
    };
    let budget = se_store::read_budget(
        None,
        SCAN_LIMIT,
        SCAN_BYTES,
        Duration::from_secs(SCAN_DEADLINE_SECS),
    );
    let page = snap.history(query, budget).map_err(|e| store_error(&e));
    let page = crate::runtime::executor::close_read(page, snap.close())?;
    let mut out = Vec::new();
    let mut last_seq = None;
    for event in page.items() {
        let seq = event.position.sequence();
        last_seq = Some(seq);
        if let Some(frame) = project::project_event(event, info, context.generation, filter)? {
            out.push((seq, frame));
        }
    }
    let truncated_at = page.next().is_some().then_some(last_seq).flatten();
    Ok(ProjectScan {
        items: out,
        truncated_at,
    })
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
