//! Common bounded submission and retained completion observer for every hosted writer.
use super::timings::{self, Mode};
use super::{CommittedWrite, ExecutionContext, failure::WriteIdentity};
use crate::client::lease::Deadline;
use se_store::{AtomicBatch, CommitReceipt, SqliteReader, StoreResult, WriterClient};
use se_types::Result;
use std::{future::Future, sync::Arc, time::Instant};

pub(crate) async fn submit(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    deadline: &Deadline,
) -> Result<CommitReceipt> {
    measured(context, batch, identity, deadline)
        .await
        .map(|value| value.0)
}
pub(super) async fn measured(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    deadline: &Deadline,
) -> Result<(CommitReceipt, Option<se_core::ops::HostPhaseSpan>, u64)> {
    let fault = context.ownership_fault.clone();
    let submitted = identity.clone();
    measured_with(
        context,
        batch,
        identity,
        deadline,
        false,
        move |writer, batch| {
            writer
                .submit(batch)
                .map(|completion| (completion, ()))
                .map_err(|error| {
                    fault.observe_writer(&error);
                    submitted.store_error(&error)
                })
        },
    )
    .await
    .map(|(receipt, submission, waited, ())| (receipt, submission, waited))
}

pub(super) async fn measured_message<T: Send + 'static>(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    deadline: &Deadline,
    readback: impl FnOnce(&SqliteReader, CommitReceipt) -> T + Send + 'static,
) -> Result<(
    CommitReceipt,
    u64,
    impl Future<Output = StoreResult<T>> + Send,
)> {
    let fault = context.ownership_fault.clone();
    let submitted = identity.clone();
    measured_with(
        context,
        batch,
        identity,
        deadline,
        true,
        move |writer, batch| {
            writer
                .submit_with_readback(batch, readback)
                .map_err(|error| {
                    fault.observe_writer(&error);
                    submitted.store_error(&error)
                })
        },
    )
    .await
    .map(|(receipt, _, waited, output)| (receipt, waited, output))
}
#[cfg(feature = "remote")]
pub(crate) async fn remote(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    deadline: &Deadline,
    permit: crate::remote::auth::AdmissionPermit,
) -> Result<CommitReceipt> {
    let fault = context.ownership_fault.clone();
    let submitted = identity.clone();
    measured_with(
        context,
        batch,
        identity,
        deadline,
        false,
        move |writer, batch| {
            permit
                .submit_with(writer, batch, |error| {
                    fault.observe_writer(error);
                    submitted.store_error(error)
                })
                .map(|completion| (completion, ()))
        },
    )
    .await
    .map(|value| value.0)
}
async fn measured_with<T: Send + 'static, Wait>(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    deadline: &Deadline,
    inline: bool,
    enqueue: impl FnOnce(&se_store::SqliteClient, AtomicBatch) -> Result<(Wait, T)> + Send + 'static,
) -> Result<(CommitReceipt, Option<se_core::ops::HostPhaseSpan>, u64, T)>
where
    Wait: Future<Output = StoreResult<CommitReceipt>> + Send + 'static,
{
    // submit performs finite bounded queue admission and serialization.
    // Preserve the returned waiter even if native work uses the final
    // part of the budget; the original request identity is unchanged.
    let recipients = super::mail::recipients(&batch);
    let revocations = super::mail::revocations(&batch);
    let custody = context.custody.get().cloned();
    let mail_waits = Arc::clone(&context.mail_waits);
    let writer = context.writer.clone();
    let submit_deadline = deadline.clone();
    let submitted = identity.clone();
    let pending = context.pending_writes.clone();
    let runtime = context.blocking.handle();
    let fault = context.ownership_fault.clone();
    let record_feed = context.atlas.records.clone();
    let submit = move || {
        submit_deadline.remaining()?;
        let record_write = record_feed.before_scoped_write(&batch.admission.scope)?;
        pending.register(&submitted)?;
        mail_waits.fence_remote(&revocations)?;
        match enqueue(&writer, batch) {
            Ok((completion, output)) => {
                // Install the observer before returning from submission:
                // a cancelled connection can drop this worker's result.
                // It holds no blocking permit while awaiting the store.
                Ok(runtime.spawn(async move {
                    let receipt = completion.await;
                    if receipt
                        .as_ref()
                        .is_err_and(|e| e.code == se_store::StoreErrorCode::CommitOutcomeUnknown)
                    {
                        record_write.uncertain();
                    } else {
                        drop(record_write);
                    }
                    if let Err(error) = &receipt {
                        fault.observe_writer(error);
                    }
                    let settled = match &receipt {
                        Ok(_) => pending.resolve(&submitted),
                        Err(error)
                            if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown =>
                        {
                            Ok(())
                        }
                        Err(_) => pending.failed_attempt(&submitted),
                    };
                    let notified = if receipt.is_ok() {
                        mail_waits
                            .remote_fence_committed(&revocations)
                            .and_then(|()| mail_waits.committed(&recipients))
                            .and_then(|()| mail_waits.revoked(&revocations))
                            .and_then(|()| {
                                custody
                                    .as_ref()
                                    .map_or(Ok(()), |custody| custody.notify_mail(&recipients))
                            })
                    } else {
                        Ok(())
                    };
                    (receipt, settled.and(notified), output)
                }))
            }
            Err(error) => {
                pending.failed_attempt(&submitted)?;
                Err(se_core::store_error::retain_write_identity(
                    error,
                    submitted.operation,
                    submitted.key.as_ref(),
                    &submitted.natural_events,
                ))
            }
        }
    };
    let (completion, submission) = if inline {
        // This path enqueues with a bounded try-send under in-memory locks.
        // The writer still owns every SQLite operation and its readback.
        (submit()?, None)
    } else {
        let (completion, phase) =
            timings::blocking(&context.blocking, Mode::Owned, deadline, submit).await?;
        (completion, Some(phase))
    };
    let waiting = Instant::now();
    let (receipt, output) = wait_for_commit(deadline, identity, completion).await?;
    Ok((
        receipt,
        submission,
        timings::micros(waiting.elapsed()),
        output,
    ))
}

async fn wait_for_commit<T>(
    deadline: &Deadline,
    identity: &WriteIdentity,
    observer: tokio::task::JoinHandle<(StoreResult<CommitReceipt>, Result<()>, T)>,
) -> Result<(CommitReceipt, T)> {
    // Neither a worker permit nor a read transaction survives here.
    // Timeout/cancel never cancels an accepted store transaction; the
    // caller must resolve/retry its original operation/natural key.
    let (receipt, settled, output) = super::pool::within(deadline, observer)
        .await
        .map_err(|error| identity.wait_error(error))?
        .map_err(|error| {
            identity.wait_error(se_core::scope::unreadable(
                "write completion observer",
                &error.to_string(),
            ))
        })?;
    let receipt = match receipt {
        Ok(receipt) => receipt,
        Err(error) => {
            let error = identity.store_error(&error);
            return Err(match settled {
                Ok(()) => error,
                Err(failure) => error.with_cause(failure),
            });
        }
    };
    let committed = CommittedWrite {
        operation: identity.operation.into(),
        key: identity.key.clone(),
        natural_events: identity.natural_events.clone(),
        committed_events: receipt.events.clone(),
    };
    settled.map_err(|error| committed.response_error(error))?;
    Ok((receipt, output))
}
