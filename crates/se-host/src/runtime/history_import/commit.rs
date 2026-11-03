//! Import uses the ordinary writer and its existing abandoned-waiter observer.
use super::super::{ExecutionContext, failure::WriteIdentity, pool::within};
use crate::client::lease::Deadline;
use se_store::{AtomicBatch, CommitReceipt, WriterClient};
use se_types::Result;
pub(super) async fn append(
    context: &ExecutionContext,
    batch: AtomicBatch,
    deadline: &Deadline,
) -> Result<CommitReceipt> {
    let identity = WriteIdentity {
        operation: "store.import_node",
        natural_key: None,
        key: batch.request.as_ref().map(|r| r.key.clone()),
        natural_events: batch
            .events
            .iter()
            .map(|e| e.header.event.clone())
            .collect(),
    };
    let original = identity.clone();
    let pending = context.pending_writes.clone();
    let writer = context.writer.clone();
    let bound = deadline.clone();
    let runtime = context.blocking.handle();
    let completion = context
        .blocking
        .run_owned(deadline, move || {
            bound.remaining()?;
            pending.register(&identity)?;
            match writer.submit(batch) {
                Ok(waiter) => Ok(runtime.spawn(async move {
                    let receipt = waiter.await;
                    let settled = match &receipt {
                        Ok(_) => pending.resolve(&identity),
                        Err(error)
                            if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown =>
                        {
                            Ok(())
                        }
                        Err(_) => pending.failed_attempt(&identity),
                    };
                    (receipt, settled)
                })),
                Err(error) => {
                    pending.failed_attempt(&identity)?;
                    Err(identity.store_error(&error))
                }
            }
        })
        .await?;
    let (receipt, settled) = within(deadline, completion)
        .await
        .map_err(|e| original.wait_error(e))?
        .map_err(|e| {
            original.wait_error(se_core::scope::unreadable(
                "import completion observer",
                &e.to_string(),
            ))
        })?;
    match receipt {
        Ok(receipt) => {
            let committed = super::super::CommittedWrite {
                operation: "store.import_node".into(),
                key: original.key,
                natural_events: original.natural_events,
                committed_events: receipt.events.clone(),
            };
            settled.map_err(|error| committed.response_error(error))?;
            Ok(receipt)
        }
        Err(error) => {
            let error = original.store_error(&error);
            Err(match settled {
                Ok(()) => error,
                Err(failure) => error.with_cause(failure),
            })
        }
    }
}

pub(super) struct CommittedRow {
    pub counts: se_store::ImportCounts,
    pub resume: Vec<super::node::ResumeFact>,
    pub reason: Option<String>,
}
// Only explicit validation refusals prove the original batch did not commit.
// Busy, I/O, generation drift and unknown outcomes retain their ordinary error.
fn row_rejection(error: &se_types::SeError) -> Option<se_store::StoreError> {
    use std::error::Error;
    if error.code() == se_types::Code::CommitOutcomeUnknown {
        return None;
    }
    let mut cause = error.source();
    while let Some(current) = cause {
        if let Some(error) = current.downcast_ref::<se_store::StoreError>() {
            return matches!(
                error.code,
                se_store::StoreErrorCode::EventInvalid | se_store::StoreErrorCode::BodyTooLarge
            )
            .then(|| error.clone());
        }
        cause = current.source();
    }
    None
}
pub(super) async fn row(
    context: &ExecutionContext,
    cx: super::node::NodeContext,
    row: super::source::Row,
    state: super::rows::RowState,
    planned: Box<super::rows::PlannedRow>,
    deadline: &Deadline,
) -> Result<CommittedRow> {
    let super::rows::PlannedRow {
        batch,
        counts,
        resume,
        reason,
    } = *planned;
    match append(context, batch, deadline).await {
        Ok(_) => Ok(CommittedRow {
            counts,
            resume,
            reason,
        }),
        Err(error) => {
            let Some(rejection) = row_rejection(&error) else {
                return Err(error);
            };
            let planned = super::job(context, deadline, move |_| {
                super::rows::rejected::plan(&cx, &row, state, rejection)
            })
            .await?;
            append(context, planned.batch, deadline).await?;
            Ok(CommittedRow {
                counts: planned.counts,
                resume: planned.resume,
                reason: planned.reason,
            })
        }
    }
}
