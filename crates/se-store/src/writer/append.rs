//! Appends commit in groups: queued requests that fit the group bounds share one
//! transaction, and each caller gets its own result with the group's timings.
use super::*;
/// Gathers queued appends behind `first` up to the group bounds. The first
/// other command stops the group and is returned to run next.
pub(super) fn collect(
    first: Request,
    receiver: &Receiver<Command>,
    options: &WriterOptions,
) -> (Vec<Request>, Option<Command>) {
    let mut group = vec![first];
    let mut bytes = group[0].materialized;
    while group.len() < options.maximum_requests.get() as usize {
        match receiver.try_recv() {
            Ok(Command::Append(r))
                if bytes + r.materialized <= options.group_bytes.get() as usize =>
            {
                bytes += r.materialized;
                group.push(r);
            }
            Ok(other) => return (group, Some(other)),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
    (group, None)
}
type Pending = (
    Reply<CommitReceipt>,
    Instant,
    usize,
    Option<se_types::IdempotencyKey>,
);
/// Commits one group under a freshly validated lease and replies to each caller.
pub(super) fn execute(
    host: &mut SqliteHost,
    lease: &dyn RuntimeLease,
    shared: &Shared,
    group: Vec<Request>,
) -> StoreResult<()> {
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
        batches.push(r.batch);
    }
    let result = host
        .engine
        .reopen(&host.reader.path, host.reader.timeout, lease)
        .and_then(|_| connection::info(&host.engine.db))
        .and_then(|i| crate::open::validate_lease(&i, lease, LeaseMode::Host))
        .and_then(|_| host.engine.group(batches, false));
    shared.set_recovering(host.engine.poisoned)?;
    match result {
        Ok((results, phases)) => deliver(shared, replies, results, &phases, start, count)?,
        Err(mut e) => {
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
            .reopen(&host.reader.path, host.reader.timeout, lease)
            .is_ok();
        shared.set_recovering(!reopened)?;
    }
    Ok(())
}
/// Sends each caller its own result, stamping committed receipts with the timings.
fn deliver(
    shared: &Shared,
    replies: Vec<Pending>,
    results: Vec<StoreResult<CommitReceipt>>,
    phases: &crate::transaction::Phases,
    start: Instant,
    count: usize,
) -> StoreResult<()> {
    if results.len() != replies.len() {
        return Err(fail(
            StoreErrorCode::CommitOutcomeUnknown,
            "writer group lost a result",
        ));
    }
    for ((reply, queued, bytes, key), mut result) in replies.into_iter().zip(results) {
        shared.completed(bytes)?;
        if let (Ok(receipt), Some(commit_sync)) = (&mut result, phases.sync) {
            receipt.write_timings = Some(WriteTimings {
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
            });
        }
        reply.send(result);
    }
    Ok(())
}
