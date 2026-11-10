//! Owned stream tasks outlive a caller's wait. A failed/partial write is never
//! retried, and a timed-out request keeps its identity until reply or failure.
use super::{
    OfferFailure, failure,
    wire::{self, Envelope, Frames},
};
use crate::{CallContext, ProviderIoPlatform, ProviderStream, ProviderTransport, StreamRead};
use se_types::{ErrorBody, Generation, Result, SeError};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::Instant,
};

pub struct Incoming {
    pub sequence: u64,
    pub message: Message,
}
pub enum Message {
    Update(Value),
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Response {
        id: u64,
        method: &'static str,
        outcome: Result<Value>,
    },
}
#[derive(Clone, Default)]
pub struct Diagnostics {
    pub stdout_terminal: bool,
    pub stdout_complete: bool,
    pub events_queued: u64,
    /// Private diagnostics can contain provider secrets; never render these bytes publicly.
    pub stderr_prefix: Vec<u8>,
    pub stderr_bytes: u64,
    pub stderr_complete: bool,
    pub stderr_truncated: bool,
    pub failure: Option<ErrorBody>,
}
struct Pending {
    method: &'static str,
    reply: oneshot::Sender<Result<Value>>,
}
pub struct Connection {
    io: Arc<dyn ProviderIoPlatform>,
    transport: Arc<ProviderTransport>,
    generation: Generation,
    next: AtomicU64,
    closing: AtomicBool,
    pending: Mutex<BTreeMap<u64, Pending>>,
    diagnostics: Mutex<Diagnostics>,
    events: mpsc::Sender<Incoming>,
    changed: tokio::sync::watch::Sender<u64>,
    writer: Arc<tokio::sync::Mutex<()>>,
    writes: tokio::sync::Mutex<JoinSet<()>>,
    readers: tokio::sync::Mutex<JoinSet<()>>,
}
impl Connection {
    pub async fn open(
        io: Arc<dyn ProviderIoPlatform>,
        transport: ProviderTransport,
        generation: Generation,
    ) -> (Arc<Self>, mpsc::Receiver<Incoming>) {
        let (events, receiver) = mpsc::channel(4);
        let connection = Arc::new(Self {
            io,
            transport: Arc::new(transport),
            generation,
            next: AtomicU64::new(1),
            closing: AtomicBool::new(false),
            pending: Mutex::new(BTreeMap::new()),
            diagnostics: Mutex::new(Diagnostics::default()),
            events,
            changed: tokio::sync::watch::channel(0).0,
            writer: Arc::new(tokio::sync::Mutex::new(())),
            writes: tokio::sync::Mutex::new(JoinSet::new()),
            readers: tokio::sync::Mutex::new(JoinSet::new()),
        });
        let mut tasks = connection.readers.lock().await;
        for stream in [ProviderStream::Output, ProviderStream::Error] {
            let owned = Arc::clone(&connection);
            tasks.spawn(async move {
                let result = owned.drain(stream).await;
                if stream == ProviderStream::Output {
                    if let Ok(mut diagnostics) = owned.diagnostics.lock() {
                        diagnostics.stdout_terminal = true;
                    }
                    owned.changed.send_modify(|v| *v = v.wrapping_add(1));
                }
                if let Err(error) = result {
                    let _ = owned.fail(error.body);
                }
            });
        }
        drop(tasks);
        (connection, receiver)
    }

    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn diagnostics(&self) -> Result<Diagnostics> {
        Ok(self
            .diagnostics
            .lock()
            .map_err(|_| failure("ACP diagnostics", "poisoned state"))?
            .clone())
    }

    pub async fn request(
        self: &Arc<Self>,
        method: &'static str,
        params: Value,
        cx: CallContext,
    ) -> Result<Value> {
        let until = until(&cx)?;
        let (_, response) = self
            .offer_until(method, params, until)
            .await
            .map_err(|e| e.error)?;
        tokio::time::timeout_at(until, response)
            .await
            .map_err(|_| {
                failure(
                    "ACP response",
                    "original request remains uncertain after its wait bound; do not replay",
                )
            })?
            .map_err(|_| {
                failure(
                    "ACP response",
                    "original reply observer closed; retain the uncertain request",
                )
            })?
    }

    /// Offer once and observe terminal completion through Message::Response.
    /// A successful write is not a provider acceptance or completion receipt.
    pub async fn offer(
        self: &Arc<Self>,
        method: &'static str,
        params: Value,
        cx: CallContext,
    ) -> Result<u64> {
        self.offer_tracked(method, params, cx)
            .await
            .map_err(|e| e.error)
    }
    /// Preserve whether this exact input crossed the native writer boundary.
    pub async fn offer_tracked(
        self: &Arc<Self>,
        method: &'static str,
        params: Value,
        cx: CallContext,
    ) -> std::result::Result<u64, OfferFailure> {
        let (id, _) = self.offer_until(method, params, until(&cx)?).await?;
        Ok(id)
    }
    async fn offer_until(
        self: &Arc<Self>,
        method: &'static str,
        params: Value,
        until: Instant,
    ) -> std::result::Result<(u64, oneshot::Receiver<Result<Value>>), OfferFailure> {
        self.require_open()?;
        let id = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| failure("ACP request identity", "identity space exhausted"))?;
        let bytes = request_frame(id, method, params)?;
        let (reply, response) = oneshot::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| failure("ACP requests", "poisoned state"))?;
            if pending.len() >= 64 {
                return Err(failure(
                    "ACP requests",
                    "64 original requests remain unsettled; no new request offered",
                )
                .into());
            }
            self.require_open()?;
            pending.insert(id, Pending { method, reply });
        }
        if let Err(offer_error) = self.send_tracked(bytes, until).await {
            if offer_error.completed_bytes == Some(0) {
                self.pending
                    .lock()
                    .map_err(|_| failure("ACP requests", "poisoned state"))?
                    .remove(&id);
            }
            return Err(offer_error);
        }
        Ok((id, response))
    }

    pub async fn notify(
        self: &Arc<Self>,
        method: &'static str,
        params: Value,
        cx: CallContext,
    ) -> Result<()> {
        let bytes = wire::encode(&json!({"jsonrpc":"2.0","method":method,"params":params}))?;
        self.send(bytes, until(&cx)?).await
    }
    pub async fn respond(
        self: &Arc<Self>,
        id: Value,
        result: Value,
        cx: CallContext,
    ) -> Result<()> {
        self.send(
            wire::encode(&json!({"jsonrpc":"2.0","id":id,"result":result}))?,
            until(&cx)?,
        )
        .await
    }
    pub async fn unsupported(self: &Arc<Self>, id: Value, cx: CallContext) -> Result<()> {
        self.send(wire::encode(&json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Client capability unavailable"}}))?, until(&cx)?).await
    }

    fn require_open(&self) -> Result<()> {
        if self.closing.load(Ordering::Acquire) {
            return Err(failure(
                "ACP connection",
                "connection is closing; original input is not replayed",
            ));
        }
        if let Some(error) = self
            .diagnostics
            .lock()
            .map_err(|_| failure("ACP diagnostics", "poisoned state"))?
            .failure
            .clone()
        {
            return Err(SeError::from(error));
        }
        Ok(())
    }
    fn fail(&self, error: ErrorBody) -> Result<()> {
        self.diagnostics
            .lock()
            .map_err(|_| failure("ACP diagnostics", "poisoned state"))?
            .failure
            .get_or_insert_with(|| error.clone());
        let pending = std::mem::take(
            &mut *self
                .pending
                .lock()
                .map_err(|_| failure("ACP requests", "poisoned state"))?,
        );
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
        for (_, pending) in pending {
            let _ = pending.reply.send(Err(SeError::from(error.clone())));
        }
        Ok(())
    }

    async fn send(self: &Arc<Self>, bytes: Vec<u8>, until: Instant) -> Result<()> {
        self.send_tracked(bytes, until).await.map_err(|e| e.error)
    }
    async fn send_tracked(
        self: &Arc<Self>,
        bytes: Vec<u8>,
        until: Instant,
    ) -> std::result::Result<(), OfferFailure> {
        self.require_open()?;
        let (completed, response) = oneshot::channel();
        let mut jobs = tokio::time::timeout_at(until, self.writes.lock())
            .await
            .map_err(|_| {
                failure(
                    "ACP write admission",
                    "writer queue is busy; original request retained",
                )
            })?;
        while let Some(joined) = jobs.try_join_next() {
            if joined.is_err() {
                let error = failure(
                    "ACP writer",
                    "owned writer panicked; partial input remains uncertain",
                );
                self.fail(error.body.clone())?;
                return Err(error.into());
            }
        }
        if jobs.len() >= 128 {
            let error = failure(
                "ACP writer",
                "128 owned writes remain unsettled; no new write offered",
            );
            self.fail(error.body.clone())?;
            return Err(error.into());
        }
        // The accepted task already owns its position in the stream. Taking
        // this lock inside a spawned task lets scheduler order splice a later
        // cancel or prompt ahead of an earlier accepted frame.
        let serial = tokio::time::timeout_at(until, self.writer.clone().lock_owned())
            .await
            .map_err(|_| {
                failure(
                    "ACP write queue",
                    "deadline before native write; original request retained",
                )
            })?;
        self.require_open()?;
        let owned = Arc::clone(self);
        jobs.spawn(async move {
            let _serial = serial;
            let result = owned.write(bytes, until).await;
            if let Err(error) = &result {
                let _ = owned.fail(error.error.body.clone());
            }
            let _ = completed.send(result);
        });
        drop(jobs);
        tokio::time::timeout_at(until, response)
            .await
            .map_err(|_| {
                OfferFailure::uncertain(failure(
                    "ACP write",
                    "owned write remains uncertain after its caller's bound; do not replay",
                ))
            })?
            .map_err(|_| {
                OfferFailure::uncertain(failure(
                    "ACP write",
                    "owned writer outcome is unavailable; do not replay",
                ))
            })?
    }
    async fn write(&self, bytes: Vec<u8>, until: Instant) -> std::result::Result<(), OfferFailure> {
        self.require_open()?;
        let expected = u32::try_from(bytes.len())
            .map_err(|_| failure("ACP write", "frame exceeds native byte count"))?;
        let written = self
            .io
            .write(&self.transport, bytes, context(self.generation, until)?)
            .await
            .map_err(OfferFailure::uncertain)?;
        if written.failure.is_some() || written.completed_bytes != expected {
            return Err(OfferFailure {
                error: written.failure.map(SeError::from).unwrap_or_else(|| {
                    failure(
                        "ACP write",
                        "partial native write; preserve the original input without replay",
                    )
                }),
                completed_bytes: Some(written.completed_bytes),
            });
        }
        Ok(())
    }

    async fn drain(&self, stream: ProviderStream) -> Result<()> {
        let maximum =
            NonZeroU32::new(64 * 1024).ok_or_else(|| failure("ACP read", "invalid chunk bound"))?;
        let mut frames = Frames::default();
        loop {
            let read = self
                .io
                .read(
                    &self.transport,
                    stream,
                    maximum,
                    CallContext::new(self.generation, Duration::from_secs(24 * 60 * 60)),
                )
                .await;
            let (bytes, terminal) = match read {
                Ok(StreamRead::Bytes(bytes)) => (bytes, None),
                Ok(StreamRead::Eof) => (Vec::new(), Some(None)),
                Ok(StreamRead::Failed { bytes, error }) => (bytes, Some(Some(error))),
                Err(error)
                    if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if stream == ProviderStream::Error {
                let mut diagnostics = self
                    .diagnostics
                    .lock()
                    .map_err(|_| failure("ACP diagnostics", "poisoned state"))?;
                diagnostics.stderr_bytes = diagnostics
                    .stderr_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| failure("ACP diagnostics", "stderr byte count overflow"))?;
                let remaining = (64 * 1024usize).saturating_sub(diagnostics.stderr_prefix.len());
                diagnostics
                    .stderr_prefix
                    .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                diagnostics.stderr_truncated |= bytes.len() > remaining;
                if let Some(terminal) = terminal {
                    diagnostics.stderr_complete = terminal.is_none();
                    drop(diagnostics);
                    return terminal.map_or(Ok(()), |body| Err(SeError::from(body)));
                }
            } else {
                for frame in frames.feed(&bytes) {
                    self.receive(frame?).await?;
                }
                if let Some(terminal) = terminal {
                    frames.eof()?;
                    if let Some(error) = terminal {
                        return Err(SeError::from(error));
                    }
                    self.diagnostics
                        .lock()
                        .map_err(|_| failure("ACP diagnostics", "poisoned state"))?
                        .stdout_complete = true;
                    if !self
                        .pending
                        .lock()
                        .map_err(|_| failure("ACP requests", "poisoned state"))?
                        .is_empty()
                    {
                        return Err(failure(
                            "ACP connection",
                            "protocol EOF; unsettled requests retain uncertain input",
                        ));
                    }
                    return Ok(());
                }
            }
        }
    }
    async fn receive(&self, frame: Envelope) -> Result<()> {
        let mut reply = None;
        let event = match frame {
            Envelope::Response { id, outcome } => {
                let original = self
                    .pending
                    .lock()
                    .map_err(|_| failure("ACP requests", "poisoned state"))?
                    .remove(&id)
                    .ok_or_else(|| {
                        failure("ACP response", "unknown or duplicate request identity")
                    })?;
                let copied = match &outcome {
                    Ok(value) => Ok(value.clone()),
                    Err(error) => Err(SeError::from(error.body.clone())),
                };
                reply = Some((original.reply, copied));
                Message::Response {
                    id,
                    method: original.method,
                    outcome,
                }
            }
            Envelope::Request { id, method, params } => Message::Request { id, method, params },
            Envelope::Update(params) => Message::Update(params),
            Envelope::OtherNotification => return Ok(()),
        };
        let sequence = self
            .diagnostics
            .lock()
            .map_err(|_| failure("ACP diagnostics", "poisoned state"))?
            .events_queued
            .checked_add(1)
            .ok_or_else(|| failure("ACP updates", "event sequence exhausted"))?;
        self.events
            .send(Incoming {
                sequence,
                message: event,
            })
            .await
            .map_err(|_| {
                failure(
                    "ACP updates",
                    "consumer closed before pending protocol work settled",
                )
            })?;
        self.diagnostics
            .lock()
            .map_err(|_| failure("ACP diagnostics", "poisoned state"))?
            .events_queued = sequence;
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
        if let Some((sender, outcome)) = reply {
            let _ = sender.send(outcome);
        }
        Ok(())
    }

    /// Close provider stdin after accepted writes settle; native stop retains
    /// responsibility for proving the resulting process/scope exit.
    pub async fn finish_input(&self, cx: CallContext) -> Result<()> {
        let until = until(&cx)?;
        join(&self.writes, until).await?;
        self.io
            .finish_input(&self.transport, context(self.generation, until)?)
            .await
    }

    /// Called only after the coordinator's native cleanup has witnessed exit.
    /// Timed-out joins stay retained in the connection for the next close.
    pub async fn close(&self, cx: CallContext) -> Result<()> {
        let until = until(&cx)?;
        self.closing.store(true, Ordering::Release);
        self.fail(
            failure(
                "ACP connection",
                "native owner is closing the witnessed scope",
            )
            .body,
        )?;
        join(&self.writes, until).await?;
        self.io
            .close(&self.transport, context(self.generation, until)?)
            .await?;
        join(&self.readers, until).await
    }
}
pub(super) fn request_frame(id: u64, method: &str, params: Value) -> Result<Vec<u8>> {
    wire::encode(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
}
async fn join(jobs: &tokio::sync::Mutex<JoinSet<()>>, until: Instant) -> Result<()> {
    let mut jobs = tokio::time::timeout_at(until, jobs.lock())
        .await
        .map_err(|_| failure("ACP task join", "owned tasks are still busy"))?;
    while let Some(result) = tokio::time::timeout_at(until, jobs.join_next())
        .await
        .map_err(|_| {
            failure(
                "ACP task join",
                "join remains retained after its wait bound",
            )
        })?
    {
        result.map_err(|_| failure("ACP task join", "owned stream task panicked"))?;
    }
    Ok(())
}
pub(super) fn until(cx: &CallContext) -> Result<Instant> {
    Instant::now()
        .checked_add(cx.timeout)
        .ok_or_else(|| failure("ACP deadline", "invalid call bound"))
}
pub(super) fn context(generation: Generation, until: Instant) -> Result<CallContext> {
    let remaining = until
        .checked_duration_since(Instant::now())
        .ok_or_else(|| failure("ACP deadline", "original wait bound expired"))?;
    Ok(CallContext::new(generation, remaining))
}
