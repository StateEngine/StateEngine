use crate::{
    completion::{self, Completion, Reply},
    connection,
    error::*,
    open::SqliteHost,
    *,
};
use std::{
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
mod atlas;
use crate::checkpoint_task;
#[expect(
    clippy::struct_excessive_bools,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
struct AdmissionState {
    bytes: usize,
    requests: usize,
    closed: bool,
    flush: bool,
    recovering: bool,
    recovery_queued: bool,
}
struct Shared {
    admission: Mutex<AdmissionState>,
    byte_limit: usize,
    request_limit: usize,
    group_limit: usize,
}
struct Request {
    batch: AtomicBatch,
    reply: Reply<CommitReceipt>,
    queued: Instant,
    bytes: usize,
    materialized: usize,
}
#[allow(
    clippy::large_enum_variant,
    reason = "Owned batches stay inline in the bounded channel; flush, drain and recovery have three reserved slots."
)]
enum Command {
    Append(Request),
    Atlas(atlas::AtlasRequest),
    Flush(Instant, Reply<FlushReport>),
    Drain(Instant),
    Recover,
}
/// Submission diagnostics belong to each completion's receipt, with no second stream.
///
/// ```compile_fail
/// fn legacy_observer(client: &se_store::SqliteClient) {
///     client.take_timings();
/// }
/// ```
#[derive(Clone)]
pub struct SqliteClient {
    sender: SyncSender<Command>,
    shared: Arc<Shared>,
    staging: Arc<StagingContext>,
}
struct StagingContext {
    path: std::path::PathBuf,
    info: StoreInfo,
    identity: LeaseIdentity,
}
impl TextStaging for SqliteClient {
    fn stage_text(
        &self,
        source: &mut dyn std::io::Read,
        maximum: u64,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<StagedText> {
        if self
            .shared
            .admission
            .lock()
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
            .closed
        {
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "writer is draining or closed",
            ));
        }
        crate::staging::stage(
            &self.staging.path,
            &self.staging.info,
            &self.staging.identity,
            source,
            maximum,
            lease,
        )
    }
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
impl WriterClient for SqliteClient {
    type Completion = Completion<CommitReceipt>;
    fn submit(&self, batch: AtomicBatch) -> StoreResult<Self::Completion> {
        let (bytes, materialized) = crate::transaction::batch_sizes(&batch)?;
        if materialized > self.shared.group_limit {
            return Err(fail(
                StoreErrorCode::BodyTooLarge,
                "request exceeds writer materialized group limit",
            ));
        }
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
        if s.recovering {
            if !s.recovery_queued && self.sender.try_send(Command::Recover).is_ok() {
                s.recovery_queued = true;
            }
            return Err(fail(
                StoreErrorCode::Busy,
                "writer reopen pending after an uncertain commit; retry the original identity",
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
                materialized,
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
    // Three reserved control slots: one flush, one coalesced recovery request,
    // and the unique owner's drain. Regular submissions remain bounded by queue_requests.
    let request_limit = options.queue_requests.get() as usize;
    let shared = Arc::new(Shared {
        admission: Mutex::new(AdmissionState {
            bytes: 0,
            requests: 0,
            closed: false,
            flush: false,
            recovering: false,
            recovery_queued: false,
        }),
        byte_limit: options.resident_bytes.get() as usize,
        request_limit,
        group_limit: options.group_bytes.get() as usize,
    });
    let (sender, receiver) = mpsc::sync_channel(request_limit + 3);
    let client = SqliteClient {
        sender,
        shared: shared.clone(),
        staging: Arc::new(StagingContext {
            path: host.reader.path.clone(),
            info: connection::info(&host.engine.db)?,
            identity,
        }),
    };
    let context = host.context.clone();
    let checkpoint = checkpoint_task::CheckpointTask::spawn(
        host.reader.path.clone(),
        host.reader.timeout,
        context.clone(),
        lease.clone(),
        host.engine.checkpoints.gate.clone(),
    )?;
    let thread = std::thread::Builder::new()
        .name("se-store-writer".into())
        .spawn(move || run(host, options, lease, receiver, shared, checkpoint))
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
        // A transient join helper keeps thread::join off the host executor. The
        // writer thread joined the checkpoint task before its final checkpoint,
        // so the returned host owns its only live connection.
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
    status: &checkpoint_task::Status,
) -> StoreResult<FlushReport> {
    if Instant::now() > deadline {
        return Err(fail(StoreErrorCode::Busy, "flush deadline exceeded"));
    }
    let recovery = host
        .engine
        .reopen(&host.reader.path, host.reader.timeout, lease);
    if let Err(error) = recovery {
        host.engine.maintenance = Some(error);
    }
    if !host.engine.poisoned
        && let Err(error) = host.checkpoint(CheckpointMode::Passive, lease)
    {
        host.engine.maintenance = Some(error);
    }
    if host.engine.maintenance.is_none() {
        // The writer's own checkpoint completed fully: it paid the pending
        // debt the background task may still be reporting, so the recovery
        // clears only that pending state before the report reads it. A
        // retained task failure is a real failure: only the task's own next
        // successful tick clears it.
        status.clear_pending();
    }
    let through = host
        .reader
        .info()
        .map_err(|mut error| {
            error.cause.push_str(&format!(
                "; indeterminate operations: {:?}",
                host.engine.indeterminate()
            ));
            error
        })?
        .head;
    Ok(FlushReport {
        maintenance_pending: host.engine.maintenance.is_some()
            || host.engine.poisoned
            || host.engine.checkpoint_pending()
            || status.pending(),
        maintenance_failed: host.engine.maintenance.is_some()
            || host.engine.poisoned
            || status.failed(),
        maintenance_error: host
            .engine
            .maintenance
            .clone()
            .or_else(|| status.last_error()),
        through,
        pending_requests: 0,
        indeterminate: host.engine.indeterminate(),
    })
}
// Idle checkpoint maintenance runs in the background checkpoint task; the
// writer blocks on its ordinary channel and performs no periodic SQLite reads.
fn receive(receiver: &Receiver<Command>) -> StoreResult<Command> {
    receiver.recv().map_err(|_| {
        fail(
            StoreErrorCode::WriterClosed,
            "writer channel ended without an owner drain",
        )
    })
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn run(
    mut host: SqliteHost,
    options: WriterOptions,
    lease: Arc<dyn RuntimeLease>,
    receiver: Receiver<Command>,
    shared: Arc<Shared>,
    checkpoint: checkpoint_task::CheckpointTask,
) -> StoreResult<DrainedHost<SqliteHost>> {
    let status = checkpoint.status().clone();
    let mut deferred = None;
    loop {
        let command = match deferred.take() {
            Some(c) => {
                status.set_idle(false);
                c
            }
            None => {
                // Blocking receive: the channel is empty, so the checkpoint
                // task may run its I/O on its own connection without
                // contending for the WAL write lock.
                status.set_idle(true);
                let command = receive(&receiver)?;
                status.set_idle(false);
                command
            }
        };
        match command {
            Command::Atlas(request) => atlas::execute(&mut host, &*lease, &shared, request)?,
            Command::Append(first) => {
                let mut group = vec![first];
                let mut bytes = group[0].materialized;
                while group.len() < options.maximum_requests.get() as usize {
                    match receiver.try_recv() {
                        Ok(Command::Append(r))
                            if bytes + r.materialized <= options.group_bytes.get() as usize =>
                        {
                            bytes += r.materialized;
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
                let result = host
                    .engine
                    .reopen(&host.reader.path, host.reader.timeout, &*lease)
                    .and_then(|_| connection::info(&host.engine.db))
                    .and_then(|i| connection::validate_lease(&i, &*lease, LeaseMode::Host))
                    .and_then(|_| host.engine.group(batches, false));
                shared
                    .admission
                    .lock()
                    .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
                    .recovering = host.engine.poisoned;
                match result {
                    Ok((results, phases)) => {
                        if results.len() != replies.len() {
                            return Err(fail(
                                StoreErrorCode::CommitOutcomeUnknown,
                                "writer group lost a result",
                            ));
                        }
                        for ((reply, queued, bytes, key), mut result) in
                            replies.into_iter().zip(results)
                        {
                            shared.completed(bytes)?;
                            if let (Ok(receipt), Some(commit_sync)) = (&mut result, phases.sync) {
                                let timings = WriteTimings {
                                    request_key: key,
                                    queue: start.saturating_duration_since(queued),
                                    transaction: phases.transaction,
                                    commit_sync,
                                    checkpoint: phases.checkpoint,
                                    group_requests: count,
                                    durability: if phases.full {
                                        CommitDurability::Full
                                    } else {
                                        CommitDurability::Normal
                                    },
                                };
                                receipt.write_timings = Some(timings);
                            }
                            reply.send(result);
                        }
                    }
                    Err(e) => {
                        let mut e = e;
                        stamp_busy_wait(&mut e, host.reader.timeout);
                        for (reply, _, bytes, _) in replies {
                            shared.completed(bytes)?;
                            reply.send(Err(e.clone()));
                        }
                    }
                }
                if host.engine.poisoned {
                    let reopened = host
                        .engine
                        .reopen(&host.reader.path, host.reader.timeout, &*lease)
                        .is_ok();
                    shared
                        .admission
                        .lock()
                        .map_err(|_| {
                            fail(StoreErrorCode::WriterClosed, "writer admission poisoned")
                        })?
                        .recovering = !reopened;
                }
            }
            Command::Recover => {
                shared
                    .admission
                    .lock()
                    .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
                    .recovery_queued = false;
                let reopened = host
                    .engine
                    .reopen(&host.reader.path, host.reader.timeout, &*lease)
                    .is_ok();
                shared
                    .admission
                    .lock()
                    .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
                    .recovering = !reopened;
            }
            Command::Flush(deadline, reply) => {
                // No join here on purpose: Pending may be spurious while the
                // task is alive, but a dead task can never be read clean.
                let result = flush(&mut host, deadline, &*lease, &status);
                shared
                    .admission
                    .lock()
                    .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
                    .flush = false;
                reply.send(result);
            }
            Command::Drain(deadline) => {
                // The report reads the task status, so the task must be dead
                // first: no tick can then move Pending between the writer's
                // final checkpoint and the read. With no live task, the
                // writer's result is the whole truth. The join itself may
                // spend the caller's remaining drain deadline; an exhausted
                // budget then surfaces as Busy from the final flush below.
                checkpoint.join();
                let report = flush(&mut host, deadline, &*lease, &status)?;
                return Ok(DrainedHost { host, report });
            }
        }
    }
}
