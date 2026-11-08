mod pump;
use super::*;
use std::{collections::BTreeMap, num::NonZeroU64, sync::Mutex as StdMutex};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::timeout,
};

type WatchSender = mpsc::Sender<Result<QueuedBatch>>;
pub(super) struct QueuedBatch {
    pub batch: RemoteWatchBatch,
    _bytes: OwnedSemaphorePermit,
}
struct Admission {
    _request: OwnedSemaphorePermit,
    _mutation: Option<OwnedSemaphorePermit>,
}
enum Pending {
    Once {
        call: Arc<RemoteCallContext>,
        tx: oneshot::Sender<Result<Reply>>,
        key: Option<String>,
        _admission: Admission,
    },
    Watch {
        call: Arc<RemoteCallContext>,
        tx: WatchSender,
        _admission: Admission,
    },
}
impl Pending {
    fn call(&self) -> &RemoteCallContext {
        match self {
            Self::Once { call, .. } | Self::Watch { call, .. } => call,
        }
    }
    fn fail(self, error: SeError) {
        match self {
            Self::Once { tx, .. } => {
                let _ = tx.send(Err(error));
            }
            Self::Watch { tx, .. } => {
                let _ = tx.try_send(Err(error));
            }
        }
    }
}
struct Outgoing {
    id: Option<RequestId>,
    text: String,
    call: Option<Arc<RemoteCallContext>>,
    _bytes: OwnedSemaphorePermit,
}
struct Shared {
    pending: StdMutex<BTreeMap<RequestId, Pending>>,
    outgoing: mpsc::Sender<Outgoing>,
    requests: Arc<Semaphore>,
    mutations: Arc<Semaphore>,
    outbound_bytes: Arc<Semaphore>,
    inbound_bytes: Arc<Semaphore>,
    stop: Arc<tokio::sync::Notify>,
    serial: AtomicU64,
    closed: AtomicBool,
    terminal: StdMutex<Option<se_types::ErrorBody>>,
}
pub(super) struct Connection {
    shared: Arc<Shared>,
    tasks: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.shared.close("client connection dropped");
        for task in self.tasks.get_mut() {
            task.abort();
        }
    }
}
pub(super) struct Guard {
    connection: Arc<Connection>,
    id: RequestId,
    cancel: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.connection.shared.pending.lock() {
            pending.remove(&self.id);
        }
        if self.cancel
            && self
                .connection
                .shared
                .enqueue(&ClientFrame::Cancel { id: self.id }, None, None)
                .is_err()
        {
            // A dropped watch must not leave an invisible server subscription.
            self.connection
                .shared
                .close("watch cancellation could not be queued; reconnect from consumed cursors");
        }
    }
}
impl Shared {
    fn close_error(&self, error: SeError) {
        if error.code() != se_types::Code::ListenerUnavailable
            && let Ok(mut terminal) = self.terminal.lock()
        {
            *terminal = Some(error.body.clone());
        }
        self.close(&error.to_string());
    }
    fn close(&self, reason: &str) {
        self.closed.store(true, Ordering::Release);
        self.stop.notify_waiters();
        self.requests.close();
        self.mutations.close();
        if let Ok(mut pending) = self.pending.lock() {
            for (_, item) in std::mem::take(&mut *pending) {
                match item {
                    Pending::Once { tx, key, .. } => {
                        let error = key
                            .map(super::unknown_send)
                            .unwrap_or_else(|| unavailable(reason));
                        let _ = tx.send(Err(error));
                    }
                    Pending::Watch { tx, .. } => {
                        let error = self
                            .terminal
                            .lock()
                            .ok()
                            .and_then(|value| value.clone())
                            .map(SeError::from)
                            .unwrap_or_else(|| unavailable(reason));
                        let _ = tx.try_send(Err(error));
                    }
                }
            }
        }
    }
    fn fail(&self, id: RequestId, error: SeError) {
        if let Ok(mut pending) = self.pending.lock()
            && let Some(item) = pending.remove(&id)
        {
            item.fail(error);
        }
    }
    fn enqueue(
        &self,
        frame: &ClientFrame,
        call: Option<Arc<RemoteCallContext>>,
        id: Option<RequestId>,
    ) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(unavailable(
                "connection is closed; reconnect using the same binding",
            ));
        }
        if let Some(call) = &call {
            call.check_current()?;
        }
        let text = wire::encode(frame, Phase::Authenticated)?;
        let bytes = self
            .outbound_bytes
            .clone()
            .try_acquire_many_owned(text.len() as u32)
            .map_err(|_| {
                unavailable(
                    "client outbound byte budget exhausted; retry after draining the connection",
                )
            })?;
        self.outgoing.try_send(Outgoing {id,text,call,_bytes:bytes})
            .map_err(|_| unavailable("client outbound frame queue is full or closed; retry without changing the request key"))
    }
    fn allocate(&self, mutation: bool) -> Result<(RequestId, Admission)> {
        let request = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable("32 in-flight requests already admitted"))?;
        let mutation = if mutation {
            Some(
                self.mutations
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| unavailable("four in-flight mutations already admitted"))?,
            )
        } else {
            None
        };
        let serial = self
            .serial
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| unavailable("request ID capacity exhausted; reconnect"))?;
        let id = RequestId(
            NonZeroU64::new(serial).ok_or_else(|| unavailable("invalid request serial"))?,
        );
        Ok((
            id,
            Admission {
                _request: request,
                _mutation: mutation,
            },
        ))
    }
    fn deliver(&self, frame: ServerFrame, encoded_bytes: usize) -> Result<()> {
        match frame {
            ServerFrame::Response { id, result } => {
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| unavailable("client request state is unreadable"))?;
                if let Some(item) = pending.get(&id)
                    && !matches!(item, Pending::Once { key: Some(_), .. })
                    && let Err(error) = item.call().check_current()
                {
                    if let Some(item) = pending.remove(&id) {
                        item.fail(error);
                    }
                    return Ok(());
                }
                if matches!(result, Reply::Watch(_)) {
                    if let (Some(Pending::Watch { tx, .. }), Reply::Watch(batch)) =
                        (pending.get(&id), result)
                    {
                        self.batch(tx, *batch, encoded_bytes)?;
                    } else {
                        return Err(unavailable("watch response does not match its request"));
                    }
                } else if let Some(Pending::Once { tx, .. }) = pending.remove(&id) {
                    let _ = tx.send(Ok(result));
                }
            }
            ServerFrame::WatchEvent { id, batch } => {
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| unavailable("client watch state is unreadable"))?;
                if let Some(Pending::Watch { call, tx, .. }) = pending.get(&id) {
                    if let Err(error) = call.check_current() {
                        if let Some(item) = pending.remove(&id) {
                            item.fail(error);
                        }
                        return Ok(());
                    }
                    self.batch(tx, *batch, encoded_bytes)?;
                }
            }
            ServerFrame::Gap {
                id,
                target,
                reason,
                reset_required,
            } => {
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| unavailable("client watch state is unreadable"))?;
                if let Some(Pending::Watch { call, tx, .. }) = pending.get(&id) {
                    if let Err(error) = call.check_current() {
                        if let Some(item) = pending.remove(&id) {
                            item.fail(error);
                        }
                        return Ok(());
                    }
                    self.batch(
                        tx,
                        RemoteWatchBatch {
                            schema: RemoteWatchBatch::SCHEMA.into(),
                            body: RemoteWatchBody {
                                records: vec![RemoteWatchRecord::Gap {
                                    target,
                                    reason,
                                    reset_required,
                                }],
                                cursors: vec![],
                                complete: false,
                                omitted_records: se_types::Omission::Unknown {
                                    reason: se_types::OmissionReason::SourceIncomplete,
                                },
                                reset_required,
                            },
                        },
                        encoded_bytes,
                    )?;
                }
            }
            ServerFrame::Error {
                id: Some(id),
                error,
            } => self.fail(id, error.into()),
            ServerFrame::Error { id: None, error } => return Err(error.into()),
            _ => return Err(unavailable("unexpected remote protocol phase")),
        }
        Ok(())
    }
    fn batch(&self, tx: &WatchSender, batch: RemoteWatchBatch, size: usize) -> Result<()> {
        if batch.schema != RemoteWatchBatch::SCHEMA {
            return Err(unavailable("watch schema mismatch"));
        }
        let bytes = self
            .inbound_bytes
            .clone()
            .try_acquire_many_owned(size as u32)
            .map_err(|_| {
                unavailable("watch byte queue overflow; reconnect from the last consumed cursors")
            })?;
        tx.try_send(Ok(QueuedBatch {
            batch,
            _bytes: bytes,
        }))
        .map_err(|_| {
            unavailable("watch frame queue overflow; reconnect from the last consumed cursors")
        })
    }
}
impl Connection {
    pub fn new(socket: super::super::channel::Socket) -> Arc<Self> {
        pump::open(socket)
    }
    pub async fn close(&self) -> Result<()> {
        self.shared.close("owning source host is closing");
        let mut tasks = self.tasks.lock().await;
        for task in tasks.iter() {
            task.abort();
        }
        // Retain each handle across cancellation and remove it only after join.
        while let Some(task) = tasks.last_mut() {
            let result = task.await;
            tasks.pop();
            if result.is_err_and(|error| !error.is_cancelled()) {
                return Err(unavailable(
                    "client task failed while joining; retry remaining transport closure",
                ));
            }
        }
        Ok(())
    }
    pub fn closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }
    pub fn check_retry(&self) -> Result<()> {
        let terminal = self.shared.terminal.lock().map_err(|_| {
            auth::refused(
                "client authority failure state is unreadable; reopen the binding after recovery",
            )
        })?;
        match terminal.as_ref() {
            Some(error) => Err(error.clone().into()),
            None => Ok(()),
        }
    }
    pub async fn once(
        self: &Arc<Self>,
        call: Arc<RemoteCallContext>,
        invocation: RemoteInvocation,
    ) -> Result<Reply> {
        let key = match &invocation.request {
            RemoteRequest::Send(r) => Some(r.idempotency_key.to_string()),
            _ => None,
        };
        let mutation = key.is_some();
        let (id, admission) = self.shared.allocate(mutation)?;
        let (tx, rx) = oneshot::channel();
        self.shared
            .pending
            .lock()
            .map_err(|_| unavailable("request state unreadable"))?
            .insert(
                id,
                Pending::Once {
                    call: call.clone(),
                    tx,
                    key: key.clone(),
                    _admission: admission,
                },
            );
        let _guard = Guard {
            connection: self.clone(),
            id,
            cancel: !mutation,
        };
        self.shared.enqueue(
            &ClientFrame::Request {
                id,
                invocation: Box::new(invocation),
            },
            Some(call.clone()),
            Some(id),
        )?;
        let result = match timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(value)) => value?,
            Ok(Err(_)) => {
                return Err(key
                    .map(super::unknown_send)
                    .unwrap_or_else(|| unavailable("remote reply channel closed")));
            }
            Err(_) => {
                return Err(key.map(super::unknown_send).unwrap_or_else(|| {
                    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
                        op: "remote request".into(),
                        deadline_ms: 30000,
                    }))
                }));
            }
        };
        if !mutation {
            call.check_current()?;
        }
        Ok(result)
    }
    pub fn subscribe(
        self: &Arc<Self>,
        call: Arc<RemoteCallContext>,
        invocation: RemoteInvocation,
    ) -> Result<(Guard, mpsc::Receiver<Result<QueuedBatch>>)> {
        let (id, admission) = self.shared.allocate(false)?;
        let (tx, rx) = mpsc::channel(REMOTE_CLIENT_QUEUE_FRAMES);
        self.shared
            .pending
            .lock()
            .map_err(|_| unavailable("watch state unreadable"))?
            .insert(
                id,
                Pending::Watch {
                    call: call.clone(),
                    tx,
                    _admission: admission,
                },
            );
        let guard = Guard {
            connection: self.clone(),
            id,
            cancel: true,
        };
        self.shared.enqueue(
            &ClientFrame::Request {
                id,
                invocation: Box::new(invocation),
            },
            Some(call),
            Some(id),
        )?;
        Ok((guard, rx))
    }
}
