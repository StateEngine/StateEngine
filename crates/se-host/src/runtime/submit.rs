//! Common bounded submission and retained completion observer for every hosted writer.
use super::timings::{self, Mode};
use super::{CommittedWrite, ExecutionContext, failure::WriteIdentity};
use crate::client::lease::Deadline;
use se_store::{AtomicBatch, CommitReceipt, WriterClient};
use se_types::Result;
use std::{sync::Arc, time::Instant};

pub(crate) enum RetainedCommit {
    /// The writer durably committed the batch. `observer_warning` preserves any
    /// secondary observer failure after commit without hiding the durable fact.
    Committed {
        observer_warning: Option<se_types::SeError>,
    },
    /// The writer itself returned `CommitOutcomeUnknown` after settling its
    /// transaction attempt; caller can reconcile via exact-record snapshot and
    /// retire `identity`.
    OutcomeUnknown(se_types::SeError),
    /// The completion observer task failed to join without a writer settlement
    /// witness. The accepted writer command may still be queued or executing,
    /// so an absent snapshot cannot clear the pending write.
    ObserverLost(se_types::SeError),
}

/// Authoritative writer settlement witness emitted by `CommitObserver`
/// immediately after `completion.await` completes, before any secondary
/// observer side-effects (record feed, mail wakes, custody) can fail or panic.
pub(super) enum WriterWitness {
    Committed(Vec<se_types::EventId>),
    OutcomeUnknown(se_types::SeError),
    DefiniteFailure(se_types::SeError),
}

/// Shared retained submission path used by both `ExecutionContext` and `Store`:
/// enqueues under `enqueue_deadline`, then awaits the writer's authoritative
/// durable outcome without cutting off an already-accepted write. If the
/// observer task fails to join after the writer already replied, the direct
/// `WriterWitness` channel preserves the exact durable outcome; only a join
/// failure with no writer settlement witness maps to `ObserverLost`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn enqueue_and_await_retained(
    blocking: &crate::BlockingPool,
    writer: se_store::SqliteClient,
    record_feed: Arc<crate::atlas_runtime::record_fence::RecordFeedFence>,
    pending: super::failure::PendingWrites,
    mail_waits: Arc<crate::http::mail::Waits>,
    fault: Arc<super::tasks::OwnershipFault>,
    custody: Option<Arc<dyn super::CustodyExecutor>>,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    enqueue_deadline: &Deadline,
) -> Result<RetainedCommit> {
    let recipients = super::mail::recipients(&batch);
    let revocations = super::mail::revocations(&batch);
    let submit_deadline = enqueue_deadline.clone();
    let submitted = identity.clone();
    let pending_after = pending.clone();
    let runtime = blocking.handle();
    let (witness_tx, mut witness_rx) = tokio::sync::oneshot::channel();
    let (completion, _submission) =
        timings::blocking(blocking, Mode::Owned, enqueue_deadline, move || {
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
                    witness: Some(witness_tx),
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
        })
        .await?;
    let (receipt, settled) = match completion.await {
        Ok(outcome) => outcome,
        Err(error) => {
            return recover_observer_join_error(identity, &pending_after, &mut witness_rx, error);
        }
    };
    match receipt {
        Ok(receipt) => {
            let observer_warning = settled.err().map(|cause| {
                CommittedWrite {
                    operation: identity.operation.into(),
                    key: identity.key.clone(),
                    natural_events: identity.natural_events.clone(),
                    committed_events: receipt.events.clone(),
                }
                .response_error(cause)
            });
            Ok(RetainedCommit::Committed { observer_warning })
        }
        Err(error) if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown => {
            let error = identity.store_error(&error);
            let error = match settled {
                Ok(()) => error,
                Err(cause) => error.with_cause(cause),
            };
            Ok(RetainedCommit::OutcomeUnknown(error))
        }
        Err(error) => {
            let error = identity.store_error(&error);
            Err(match settled {
                Ok(()) => error,
                Err(cause) => error.with_cause(cause),
            })
        }
    }
}

/// Submit a batch under `enqueue_deadline`, then await the writer's authoritative
/// durable outcome without cutting off an already-accepted write on a short request deadline.
fn recover_observer_join_error(
    identity: &WriteIdentity,
    pending: &super::failure::PendingWrites,
    witness_rx: &mut tokio::sync::oneshot::Receiver<WriterWitness>,
    error: tokio::task::JoinError,
) -> Result<RetainedCommit> {
    let observer_err = se_core::scope::unreadable("write completion observer", &error.to_string());
    match witness_rx.try_recv() {
        Ok(WriterWitness::Committed(committed_events)) => {
            let _ = pending.resolve(identity);
            let warning = CommittedWrite {
                operation: identity.operation.into(),
                key: identity.key.clone(),
                natural_events: identity.natural_events.clone(),
                committed_events,
            }
            .response_error(observer_err);
            Ok(RetainedCommit::Committed {
                observer_warning: Some(warning),
            })
        }
        Ok(WriterWitness::OutcomeUnknown(store_err)) => Ok(RetainedCommit::OutcomeUnknown(
            store_err.with_cause(observer_err),
        )),
        Ok(WriterWitness::DefiniteFailure(store_err)) => {
            let _ = pending.failed_attempt(identity);
            Err(store_err.with_cause(observer_err))
        }
        Err(_) => Ok(RetainedCommit::ObserverLost(
            identity.wait_error(observer_err),
        )),
    }
}

pub(crate) async fn submit_retained(
    context: &ExecutionContext,
    batch: AtomicBatch,
    identity: &WriteIdentity,
    enqueue_deadline: &Deadline,
) -> Result<RetainedCommit> {
    enqueue_and_await_retained(
        &context.blocking,
        context.writer.clone(),
        context.atlas.records.clone(),
        context.pending_writes.clone(),
        Arc::clone(&context.mail_waits),
        context.ownership_fault.clone(),
        context.custody.get().cloned(),
        batch,
        identity,
        enqueue_deadline,
    )
    .await
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
                        witness: None,
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
    pub(super) witness: Option<tokio::sync::oneshot::Sender<WriterWitness>>,
}

impl CommitObserver {
    pub(super) fn spawn(
        self,
        runtime: &tokio::runtime::Handle,
    ) -> tokio::task::JoinHandle<(se_store::StoreResult<CommitReceipt>, Result<()>)> {
        runtime.spawn(async move {
            let receipt = self.completion.await;
            if let Some(tx) = self.witness {
                let witness = match &receipt {
                    Ok(committed) => WriterWitness::Committed(committed.events.clone()),
                    Err(error) if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown => {
                        WriterWitness::OutcomeUnknown(self.submitted.store_error(error))
                    }
                    Err(error) => WriterWitness::DefiniteFailure(self.submitted.store_error(error)),
                };
                let _ = tx.send(witness);
            }
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
