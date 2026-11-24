//! Import commits through the host's ordinary writer; one refused row is retained.
use super::Context;
use se_harness::Deadline;
use se_store::{AtomicBatch, CommitReceipt};
use se_types::Result;
pub(super) async fn append(
    context: &Context,
    batch: AtomicBatch,
    deadline: &Deadline,
) -> Result<CommitReceipt> {
    context.append(batch, deadline).await
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
    context: &Context,
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
