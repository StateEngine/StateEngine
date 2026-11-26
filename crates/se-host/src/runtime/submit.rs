//! Common bounded submission and retained completion observer for every hosted writer.
use super::timings::{self, Mode};
use super::{CommittedWrite, ExecutionContext, failure::WriteIdentity};
use crate::client::lease::Deadline;
use se_store::{AtomicBatch, CommitReceipt, WriterClient};
use se_types::Result;
use std::{sync::Arc, time::Instant};

pub(crate) enum RetainedCommit {
    /// The writer durably committed the batch (even if a secondary observer step warned).
    Committed(CommitReceipt),
    /// The writer reported an indeterminate commit outcome; caller must reconcile.
    OutcomeUnknown(se_types::SeError),
}

/// Submit a batch under `enqueue_deadline`, then await the writer's authoritative
/// durable outcome without cutting off an already-accepted write on a short request deadline.
pub(crate) async fn submit_retained(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    enqueue_deadline: &Deadline,
) -> Result<RetainedCommit> {
    let recipients = super::mail::recipients(&batch);
    let revocations = super::mail::revocations(&batch);
    let custody = context.custody.get().cloned();
    let mail_waits = Arc::clone(&context.mail_waits);
    let writer = context.writer.clone();
    let submit_deadline = enqueue_deadline.clone();
    let submitted = identity.clone();
    let pending = context.pending_writes.clone();
    let runtime = context.blocking.handle();
    let fault = context.ownership_fault.clone();
    let record_feed = context.atlas.records.clone();
    let (completion, _submission) = timings::blocking(
        &context.blocking,
        Mode::Owned,
        enqueue_deadline,
        move || {
            submit_deadline.remaining()?;
            let record_write = record_feed.before_scoped_write(&batch.admission.scope)?;
            pending.register(&submitted)?;
            mail_waits.fence_remote(&revocations)?;
            match writer.submit(batch) {
                Ok(completion) => Ok(CommitObserver {
                    completion,
                    record_write,
                    fault,
                    pending,
                    submitted,
                    mail_waits,
                    revocations,
                    recipients,
                    custody,
                }
                .spawn(&runtime)),
                Err(error) => {
                    fault.observe_writer(&error);
                    let error = submitted.store_error(&error);
                    pending.failed_attempt(&submitted)?;
                    Err(se_core::store_error::retain_write_identity(
                        error,
                        submitted.operation,
                        submitted.key.as_ref(),
                        &submitted.natural_events,
                    ))
                }
            }
        },
    )
    .await?;
    let (receipt, _settled) = completion.await.map_err(|error| {
        identity.wait_error(se_core::scope::unreadable(
            "write completion observer",
            &error.to_string(),
        ))
    })?;
    match receipt {
        Ok(receipt) => Ok(RetainedCommit::Committed(receipt)),
        Err(error) if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown => {
            Ok(RetainedCommit::OutcomeUnknown(identity.store_error(&error)))
        }
        Err(error) => Err(identity.store_error(&error)),
    }
}

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
) -> Result<(CommitReceipt, se_core::ops::HostPhaseSpan, u64)> {
    let fault = context.ownership_fault.clone();
    let submitted = identity.clone();
    measured_with(context, batch, identity, deadline, move |writer, batch| {
        writer.submit(batch).map_err(|error| {
            fault.observe_writer(&error);
            submitted.store_error(&error)
        })
    })
    .await
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
    measured_with(context, batch, identity, deadline, move |writer, batch| {
        permit.submit_with(writer, batch, |error| {
            fault.observe_writer(error);
            submitted.store_error(error)
        })
    })
    .await
    .map(|value| value.0)
}
async fn measured_with(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    deadline: &Deadline,
    enqueue: impl FnOnce(
        &se_store::SqliteClient,
        AtomicBatch,
    ) -> Result<<se_store::SqliteClient as WriterClient>::Completion>
    + Send
    + 'static,
) -> Result<(CommitReceipt, se_core::ops::HostPhaseSpan, u64)> {
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
    let (completion, submission) =
        timings::blocking(&context.blocking, Mode::Owned, deadline, move || {
            submit_deadline.remaining()?;
            let record_write = record_feed.before_scoped_write(&batch.admission.scope)?;
            pending.register(&submitted)?;
            mail_waits.fence_remote(&revocations)?;
            match enqueue(&writer, batch) {
                Ok(completion) => {
                    // Install the observer before returning from submission:
                    // a cancelled connection can drop this worker's result.
                    // It holds no blocking permit while awaiting the store.
                    Ok(CommitObserver {
                        completion,
                        record_write,
                        fault,
                        pending,
                        submitted,
                        mail_waits,
                        revocations,
                        recipients,
                        custody,
                    }
                    .spawn(&runtime))
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
        })
        .await?;
    // Neither a worker permit nor a read transaction survives here.
    // Timeout/cancel never cancels an accepted store transaction; the
    // caller must resolve/retry its original operation/natural key.
    let waiting = Instant::now();
    let (receipt, settled) = super::pool::within(deadline, completion)
        .await
        .map_err(|error| identity.wait_error(error))?
        .map_err(|error| {
            identity.wait_error(se_core::scope::unreadable(
                "write completion observer",
                &error.to_string(),
            ))
        })?;
    let completion_wait_us = timings::micros(waiting.elapsed());
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
    Ok((receipt, submission, completion_wait_us))
}

pub(super) struct CommitObserver {
    pub(super) completion: <se_store::SqliteClient as WriterClient>::Completion,
    pub(super) record_write: crate::atlas_runtime::record_fence::RecordFeedWrite,
    pub(super) fault: Arc<super::tasks::OwnershipFault>,
    pub(super) pending: super::failure::PendingWrites,
    pub(super) submitted: WriteIdentity,
    pub(super) mail_waits: Arc<crate::http::mail::Waits>,
    pub(super) revocations: super::mail::Revocations,
    pub(super) recipients: Vec<super::mail::MailRecipient>,
    pub(super) custody: Option<Arc<dyn super::CustodyExecutor>>,
}

impl CommitObserver {
    pub(super) fn spawn(
        self,
        runtime: &tokio::runtime::Handle,
    ) -> tokio::task::JoinHandle<(se_store::StoreResult<CommitReceipt>, Result<()>)> {
        runtime.spawn(async move {
            let receipt = self.completion.await;
            if receipt
                .as_ref()
                .is_err_and(|e| e.code == se_store::StoreErrorCode::CommitOutcomeUnknown)
            {
                self.record_write.uncertain();
            } else {
                drop(self.record_write);
            }
            if let Err(error) = &receipt {
                self.fault.observe_writer(error);
            }
            let settled = match &receipt {
                Ok(_) => self.pending.resolve(&self.submitted),
                Err(error) if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown => {
                    Ok(())
                }
                Err(_) => self.pending.failed_attempt(&self.submitted),
            };
            let notified = if receipt.is_ok() {
                self.mail_waits
                    .remote_fence_committed(&self.revocations)
                    .and_then(|()| self.mail_waits.committed(&self.recipients))
                    .and_then(|()| self.mail_waits.revoked(&self.revocations))
                    .and_then(|()| {
                        self.custody
                            .as_ref()
                            .map_or(Ok(()), |custody| custody.notify_mail(&self.recipients))
                    })
            } else {
                Ok(())
            };
            (receipt, settled.and(notified))
        })
    }
}
