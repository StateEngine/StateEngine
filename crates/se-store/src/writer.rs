use crate::{
    completion::{self, Completion, Reply},
    connection,
    error::*,
    open::SqliteHost,
    *,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    time::{Duration, Instant},
};
/// Diagnostic observations, separate from immutable commit receipts. The sync
/// interval is SQLite COMMIT call time, not a claimed count/duration of OS fsyncs.
#[derive(Clone, Debug)]
pub struct WriteTimings {
    pub request_key: Option<se_types::IdempotencyKey>,
    pub queue: Duration,
    pub transaction: Duration,
    pub commit_sync: Duration,
    pub checkpoint: Duration,
    pub group_requests: usize,
}
struct Shared {
    bytes: AtomicUsize,
    closed: AtomicBool,
    limit: usize,
    timings: Mutex<VecDeque<WriteTimings>>,
}
struct Request {
    batch: AtomicBatch,
    reply: Reply<CommitReceipt>,
    queued: Instant,
    bytes: usize,
}
enum Command {
    Append(Request),
    Flush(Instant, Reply<FlushReport>),
    Drain(Instant, Reply<DrainedHost<SqliteHost>>),
}
#[derive(Clone)]
pub struct SqliteClient {
    sender: SyncSender<Command>,
    shared: Arc<Shared>,
}
pub struct SqliteWriter {
    client: SqliteClient,
    context: BackupContext,
}
impl SqliteClient {
    /// Bounded diagnostic buffer; draining observations has no storage side effect.
    pub fn take_timings(&self) -> StoreResult<Vec<WriteTimings>> {
        let mut q = self.shared.timings.lock().map_err(|_| {
            fail(
                StoreErrorCode::WriterClosed,
                "writer timing buffer poisoned",
            )
        })?;
        Ok(q.drain(..).collect())
    }
}
impl WriterClient for SqliteClient {
    type Completion = Completion<CommitReceipt>;
    fn submit(&self, batch: AtomicBatch) -> StoreResult<Self::Completion> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "writer is draining or closed",
            ));
        }
        let bytes = crate::transaction::batch_bytes(&batch)?;
        if self
            .shared
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes).filter(|v| *v <= self.shared.limit)
            })
            .is_err()
        {
            return Err(fail(
                StoreErrorCode::Backpressure,
                "writer resident byte limit reached",
            ));
        }
        let (reply, wait) = completion::channel();
        let command = Command::Append(Request {
            batch,
            reply,
            queued: Instant::now(),
            bytes,
        });
        match self.sender.try_send(command) {
            Ok(()) => Ok(wait),
            Err(e) => {
                self.shared.bytes.fetch_sub(bytes, Ordering::AcqRel);
                Err(fail(
                    match e {
                        TrySendError::Full(_) => StoreErrorCode::Backpressure,
                        TrySendError::Disconnected(_) => StoreErrorCode::WriterClosed,
                    },
                    "writer queue did not accept request",
                ))
            }
        }
    }
}
pub(crate) fn start(
    host: SqliteHost,
    options: WriterOptions,
    lease: Arc<dyn RuntimeLease>,
) -> StoreResult<SqliteWriter> {
    let identity = connection::validate_lease(
        &connection::info(&host.engine.db)?,
        &*lease,
        LeaseMode::Host,
    )?;
    if identity.generation != host.engine.identity.generation {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "writer lease differs from maintenance owner",
        ));
    }
    if options.maximum_requests.get() > 256
        || options.queue_requests.get() > 256
        || options.resident_bytes.get() > 8 * 1024 * 1024
        || options.group_bytes.get() > 2 * 1024 * 1024
    {
        return Err(invalid("writer options exceed bounded request/byte limits"));
    }
    let shared = Arc::new(Shared {
        bytes: AtomicUsize::new(0),
        closed: AtomicBool::new(false),
        limit: options.resident_bytes.get() as usize,
        timings: Mutex::new(VecDeque::new()),
    });
    let (sender, receiver) = mpsc::sync_channel(options.queue_requests.get() as usize);
    let client = SqliteClient {
        sender,
        shared: shared.clone(),
    };
    let context = host.context.clone();
    std::thread::Builder::new()
        .name("se-store-writer".into())
        .spawn(move || run(host, options, lease, receiver, shared))
        .map_err(invalid)?;
    Ok(SqliteWriter { client, context })
}
impl WriterOwner for SqliteWriter {
    type Host = SqliteHost;
    type Client = SqliteClient;
    type Flush = Completion<FlushReport>;
    type Drain = Completion<DrainedHost<SqliteHost>>;
    fn client(&self) -> Self::Client {
        self.client.clone()
    }
    fn backup_context(&self) -> BackupContext {
        self.context.clone()
    }
    fn flush(&mut self, deadline: Duration) -> StoreResult<Self::Flush> {
        let (reply, wait) = completion::channel();
        self.client
            .sender
            .try_send(Command::Flush(Instant::now() + deadline, reply))
            .map_err(|_| fail(StoreErrorCode::Backpressure, "flush barrier not accepted"))?;
        Ok(wait)
    }
    fn drain(self, deadline: Duration) -> Self::Drain {
        self.client.shared.closed.store(true, Ordering::Release);
        let (reply, wait) = completion::channel();
        // Closing admission precedes this finite send. A full queue is a truthful
        // refusal, never a blocking wait on the host executor.
        if let Err(e) = self
            .client
            .sender
            .try_send(Command::Drain(Instant::now() + deadline, reply))
        {
            if let TrySendError::Full(Command::Drain(_, reply))
            | TrySendError::Disconnected(Command::Drain(_, reply)) = e
            {
                reply.send(Err(fail(
                    StoreErrorCode::Backpressure,
                    "drain barrier could not enter queue; writer remains owned",
                )))
            }
        }
        wait
    }
}
fn flush(
    host: &mut SqliteHost,
    deadline: Instant,
    lease: &dyn RuntimeLease,
) -> StoreResult<FlushReport> {
    if Instant::now() > deadline {
        return Err(fail(StoreErrorCode::Busy, "flush deadline exceeded"));
    }
    host.checkpoint(CheckpointMode::Passive, lease)?;
    Ok(FlushReport {
        through: connection::info(&host.engine.db)?.head,
        pending_requests: 0,
        indeterminate: Vec::new(),
    })
}
fn run(
    mut host: SqliteHost,
    options: WriterOptions,
    lease: Arc<dyn RuntimeLease>,
    receiver: Receiver<Command>,
    shared: Arc<Shared>,
) {
    let mut deferred = None;
    loop {
        let command = match deferred.take() {
            Some(c) => c,
            None => match receiver.recv() {
                Ok(c) => c,
                Err(_) => break,
            },
        };
        match command {
            Command::Append(first) => {
                let mut group = vec![first];
                let mut bytes = group[0].bytes;
                while group.len() < options.maximum_requests.get() as usize {
                    match receiver.try_recv() {
                        Ok(Command::Append(r))
                            if bytes + r.bytes <= options.group_bytes.get() as usize =>
                        {
                            bytes += r.bytes;
                            group.push(r)
                        }
                        Ok(other) => {
                            deferred = Some(other);
                            break;
                        }
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                    }
                }
                let start = Instant::now();
                let count = group.len();
                let mut replies = Vec::new();
                let mut batches = Vec::new();
                for request in group {
                    replies.push((
                        request.reply,
                        request.queued,
                        request.bytes,
                        request.batch.request.as_ref().map(|r| r.key.clone()),
                    ));
                    batches.push(request.batch)
                }
                let result = connection::info(&host.engine.db)
                    .and_then(|info| connection::validate_lease(&info, &*lease, LeaseMode::Host))
                    .and_then(|_| host.engine.group(batches, false));
                match result {
                    Ok((results, phases)) => {
                        for ((reply, queued, bytes, key), result) in
                            replies.into_iter().zip(results)
                        {
                            shared.bytes.fetch_sub(bytes, Ordering::AcqRel);
                            if let Ok(mut q) = shared.timings.lock() {
                                if q.len() == 1024 {
                                    q.pop_front();
                                }
                                q.push_back(WriteTimings {
                                    request_key: key,
                                    queue: start.saturating_duration_since(queued),
                                    transaction: phases.transaction,
                                    commit_sync: phases.sync,
                                    checkpoint: phases.checkpoint,
                                    group_requests: count,
                                });
                            }
                            reply.send(result);
                        }
                    }
                    Err(error) => {
                        for (reply, _, bytes, _) in replies {
                            shared.bytes.fetch_sub(bytes, Ordering::AcqRel);
                            reply.send(Err(error.clone()));
                        }
                    }
                }
            }
            Command::Flush(deadline, reply) => reply.send(flush(&mut host, deadline, &*lease)),
            Command::Drain(deadline, reply) => {
                let result = flush(&mut host, deadline, &*lease);
                match result {
                    Ok(report) => reply.send(Ok(DrainedHost { host, report })),
                    Err(error) => reply.send(Err(error)),
                };
                return;
            }
        }
    }
    shared.closed.store(true, Ordering::Release);
}
