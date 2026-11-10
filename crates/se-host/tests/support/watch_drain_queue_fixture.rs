//! A decoded-wire producer using the real admission, queue and byte accounting.
use super::*;
pub(in crate::remote::client) struct Queue {
    pub connection: Arc<Connection>,
    id: RequestId,
    guard: Option<Guard>,
    receiver: Option<mpsc::Receiver<Result<QueuedBatch>>>,
    _outgoing: mpsc::Receiver<Outgoing>,
}
impl Queue {
    pub fn new(call: Arc<RemoteCallContext>, invocation: RemoteInvocation) -> Result<Self> {
        let (outgoing, receiver) = mpsc::channel(REMOTE_CLIENT_QUEUE_FRAMES);
        let connection = Arc::new(Connection {
            shared: Arc::new(Shared {
                pending: StdMutex::new(BTreeMap::new()),
                outgoing,
                requests: Arc::new(Semaphore::new(REMOTE_MAX_REQUESTS)),
                mutations: Arc::new(Semaphore::new(REMOTE_MAX_MUTATIONS)),
                outbound_bytes: Arc::new(Semaphore::new(REMOTE_CLIENT_QUEUE_BYTES)),
                inbound_bytes: Arc::new(Semaphore::new(REMOTE_CLIENT_QUEUE_BYTES)),
                stop: Arc::new(tokio::sync::Notify::new()),
                serial: AtomicU64::new(1),
                closed: AtomicBool::new(false),
                terminal: StdMutex::new(None),
            }),
            tasks: tokio::sync::Mutex::new(Vec::new()),
        });
        let (guard, rx) = connection.subscribe(call, invocation)?;
        Ok(Self {
            id: guard.id,
            connection,
            guard: Some(guard),
            receiver: Some(rx),
            _outgoing: receiver,
        })
    }
    pub fn take(
        &mut self,
    ) -> Result<(Arc<Connection>, Guard, mpsc::Receiver<Result<QueuedBatch>>)> {
        Ok((
            self.connection.clone(),
            self.guard
                .take()
                .ok_or_else(|| unavailable("fixture attachment already taken"))?,
            self.receiver
                .take()
                .ok_or_else(|| unavailable("fixture receiver already taken"))?,
        ))
    }
    pub fn feed(&self, batch: RemoteWatchBatch) -> Result<()> {
        let frame = ServerFrame::WatchEvent {
            id: self.id,
            batch: Box::new(batch),
        };
        let bytes = wire::encode(&frame, Phase::Authenticated)?.len();
        self.connection.shared.deliver(frame, bytes)
    }
    pub fn available_bytes(&self) -> usize {
        self.connection.shared.inbound_bytes.available_permits()
    }
}
