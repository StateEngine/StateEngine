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
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
/// Diagnostics separate from immutable receipts. commit_sync measures SQLite's
/// COMMIT call, not a claimed filesystem syscall duration/count.
#[derive(Clone, Debug)]
pub struct WriteTimings {
    pub request_key: Option<se_types::IdempotencyKey>,
    pub queue: Duration,
    pub transaction: Duration,
    pub commit_sync: Duration,
    pub checkpoint: Duration,
    pub group_requests: usize,
}
struct AdmissionState {
    bytes: usize,
    requests: usize,
    closed: bool,
    flush: bool,
}
struct Shared {
    admission: Mutex<AdmissionState>,
    byte_limit: usize,
    request_limit: usize,
    timings: Mutex<VecDeque<WriteTimings>>,
}
struct Request {
    batch: AtomicBatch,
    reply: Reply<CommitReceipt>,
    queued: Instant,
    bytes: usize,
}
#[allow(
    clippy::large_enum_variant,
    reason = "Owned batches stay inline in the bounded channel; control messages are at most two reserved slots."
)]
enum Command {
    Append(Request),
    Flush(Instant, Reply<FlushReport>),
    Drain(Instant),
}
#[derive(Clone)]
pub struct SqliteClient {
    sender: SyncSender<Command>,
    shared: Arc<Shared>,
}
pub struct SqliteWriter {
    client: SqliteClient,
    context: BackupContext,
    thread: Option<JoinHandle<StoreResult<DrainedHost<SqliteHost>>>>,
}
impl Shared {
    fn completed(&self, bytes: usize) -> StoreResult<()> {
        let mut s = self
            .admission
            .lock()
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?;
        s.bytes = s
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| invalid("writer byte accounting underflow"))?;
        s.requests = s
            .requests
            .checked_sub(1)
            .ok_or_else(|| invalid("writer request accounting underflow"))?;
        Ok(())
    }
}
impl SqliteClient {
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
        let bytes = crate::transaction::batch_bytes(&batch)?;
        // Serialize admission with the drain barrier, so no accepted request can
        // enter behind it. The lock protects counters only, never SQLite work.
        let mut s = self
            .shared
            .admission
            .lock()
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?;
        if s.closed {
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "writer is draining or closed",
            ));
        }
        let next = s
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("writer byte accounting overflow"))?;
        if next > self.shared.byte_limit || s.requests == self.shared.request_limit {
            return Err(fail(
                StoreErrorCode::Backpressure,
                "writer request/resident byte bound reached",
            ));
        }
        let (reply, wait) = completion::channel();
        self.sender
            .try_send(Command::Append(Request {
                batch,
                reply,
                queued: Instant::now(),
                bytes,
            }))
            .map_err(|e| {
                fail(
                    match e {
                        TrySendError::Full(_) => StoreErrorCode::Backpressure,
                        TrySendError::Disconnected(_) => StoreErrorCode::WriterClosed,
                    },
                    "writer did not accept the operation",
                )
            })?;
        s.bytes = next;
        s.requests += 1;
        Ok(wait)
    }
}
pub(crate) fn start(
    mut host: SqliteHost,
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
        || options.resident_bytes.get() > 1024 * 1024
        || options.group_bytes.get() > 2 * 1024 * 1024
    {
        return Err(invalid("writer options exceed bounded request/byte limits"));
    }
    match host.runtime_owner()? {
        se_types::Read::Present { value: owner }
            if owner.generation.get() == identity.generation && owner.handover.is_none() => {}
        _ => {
            return Err(fail(
                StoreErrorCode::GenerationChanged,
                "writer startup requires the committed matching runtime owner without an unresolved transfer",
            ));
        }
    }
    host.lease = Some(lease.clone());
    // Two reserved control slots: at most one pending flush, and the unique
    // owner's drain. Regular submissions remain bounded by queue_requests.
    let request_limit = options.queue_requests.get() as usize;
    let shared = Arc::new(Shared {
        admission: Mutex::new(AdmissionState {
            bytes: 0,
            requests: 0,
            closed: false,
            flush: false,
        }),
        byte_limit: options.resident_bytes.get() as usize,
        request_limit,
        timings: Mutex::new(VecDeque::new()),
    });
    let (sender, receiver) = mpsc::sync_channel(request_limit + 2);
    let client = SqliteClient {
        sender,
        shared: shared.clone(),
    };
    let context = host.context.clone();
    let thread = std::thread::Builder::new()
        .name("se-store-writer".into())
        .spawn(move || run(host, options, lease, receiver, shared))
        .map_err(invalid)?;
    Ok(SqliteWriter {
        client,
        context,
        thread: Some(thread),
    })
}
impl SqliteWriter {
    fn seal(&self, deadline: Duration) -> StoreResult<()> {
        let mut s = self
            .client
            .shared
            .admission
            .lock()
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?;
        if s.closed {
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "writer already draining",
            ));
        }
        s.closed = true;
        self.client
            .sender
            .try_send(Command::Drain(Instant::now() + deadline))
            .map_err(|_| {
                fail(
                    StoreErrorCode::WriterClosed,
                    "writer drain receiver is gone",
                )
            })
    }
}
impl Drop for SqliteWriter {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.seal(Duration::from_secs(5));
        }
    }
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
        let mut s = self
            .client
            .shared
            .admission
            .lock()
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?;
        if s.closed || s.flush {
            return Err(fail(
                StoreErrorCode::Backpressure,
                "writer closed or flush already pending",
            ));
        }
        let (reply, wait) = completion::channel();
        self.client
            .sender
            .try_send(Command::Flush(Instant::now() + deadline, reply))
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "flush receiver is gone"))?;
        s.flush = true;
        Ok(wait)
    }
    fn drain(mut self, deadline: Duration) -> Self::Drain {
        let (reply, wait) = completion::channel();
        if let Err(e) = self.seal(deadline) {
            reply.send(Err(e));
            return wait;
        }
        let Some(thread) = self.thread.take() else {
            reply.send(Err(fail(
                StoreErrorCode::WriterClosed,
                "writer join ownership absent",
            )));
            return wait;
        };
        // A transient join helper keeps thread::join off the host executor and
        // releases the maintenance object only after the writer actually exits.
        let _ = std::thread::Builder::new()
            .name("se-store-join".into())
            .spawn(move || {
                let result = thread.join().unwrap_or_else(|_| {
                    Err(fail(
                        StoreErrorCode::CommitOutcomeUnknown,
                        "writer panicked; resolve original operation keys",
                    ))
                });
                reply.send(result);
            });
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
) -> StoreResult<DrainedHost<SqliteHost>> {
    let mut deferred = None;
    loop {
        let command = match deferred.take() {
            Some(c) => c,
            None => receiver.recv().map_err(|_| {
                fail(
                    StoreErrorCode::WriterClosed,
                    "writer channel ended without an owner drain",
                )
            })?,
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
                for r in group {
                    replies.push((
                        r.reply,
                        r.queued,
                        r.bytes,
                        r.batch.request.as_ref().map(|r| r.key.clone()),
                    ));
                    batches.push(r.batch)
                }
                let result = connection::info(&host.engine.db)
                    .and_then(|i| connection::validate_lease(&i, &*lease, LeaseMode::Host))
                    .and_then(|_| host.engine.group(batches, false));
                match result {
                    Ok((results, phases)) => {
                        if results.len() != replies.len() {
                            return Err(fail(
                                StoreErrorCode::CommitOutcomeUnknown,
                                "writer group lost a result",
                            ));
                        }
                        for ((reply, queued, bytes, key), result) in
                            replies.into_iter().zip(results)
                        {
                            shared.completed(bytes)?;
                            let mut q = shared.timings.lock().map_err(|_| {
                                fail(
                                    StoreErrorCode::WriterClosed,
                                    "writer timing buffer poisoned",
                                )
                            })?;
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
                            drop(q);
                            reply.send(result);
                        }
                    }
                    Err(e) => {
                        for (reply, _, bytes, _) in replies {
                            shared.completed(bytes)?;
                            reply.send(Err(e.clone()));
                        }
                    }
                }
            }
            Command::Flush(deadline, reply) => {
                let result = flush(&mut host, deadline, &*lease);
                shared
                    .admission
                    .lock()
                    .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
                    .flush = false;
                reply.send(result);
            }
            Command::Drain(deadline) => {
                let report = flush(&mut host, deadline, &*lease)?;
                return Ok(DrainedHost { host, report });
            }
        }
    }
}
