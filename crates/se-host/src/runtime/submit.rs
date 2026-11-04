//! Common bounded submission and retained completion observer for every hosted writer.
use super::timings::{self, Mode};
use super::{CommittedWrite, ExecutionContext, failure::WriteIdentity};
use crate::client::lease::Deadline;
use se_store::{AtomicBatch, CommitReceipt, WriterClient};
use se_types::Result;
use std::{sync::Arc, time::Instant};

#[cfg(feature = "secode")]
pub(super) async fn submit(
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
    // submit performs finite bounded queue admission and serialization.
    // Preserve the returned waiter even if native work uses the final
    // part of the budget; the original request identity is unchanged.
    let recipients = super::mail::recipients(&batch);
    let custody = context.custody.get().cloned();
    let mail_waits = Arc::clone(&context.mail_waits);
    let writer = context.writer.clone();
    let submit_deadline = deadline.clone();
    let submitted = identity.clone();
    let pending = context.pending_writes.clone();
    let runtime = context.blocking.handle();
    let (completion, submission) =
        timings::blocking(&context.blocking, Mode::Owned, deadline, move || {
            submit_deadline.remaining()?;
            pending.register(&submitted)?;
            match writer.submit(batch) {
                Ok(completion) => {
                    // Install the observer before returning from submission:
                    // a cancelled connection can drop this worker's result.
                    // It holds no blocking permit while awaiting the store.
                    Ok(runtime.spawn(async move {
                        let receipt = completion.await;
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
                            mail_waits.committed().and_then(|()| {
                                custody
                                    .as_ref()
                                    .map_or(Ok(()), |custody| custody.notify_mail(&recipients))
                            })
                        } else {
                            Ok(())
                        };
                        (receipt, settled.and(notified))
                    }))
                }
                Err(error) => {
                    pending.failed_attempt(&submitted)?;
                    Err(submitted.store_error(&error))
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
