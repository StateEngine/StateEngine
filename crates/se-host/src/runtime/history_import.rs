//! Host side of owner history import: foreground jobs, generation-checked read
//! pins, the ordinary writer with its abandoned-waiter observer, and the
//! active owner profiles. The import logic lives in `se-history-import`.
use super::{BlockingClass, ExecutionContext, executor, failure::WriteIdentity, pool::within};
use crate::client::lease::Deadline;
use se_core::{admission::read_scope, ops::AnyOutput, store_error::store_error};
use se_history_import::{BlockingWork, HistoryPort, PortFuture, ReadPin};
use se_store::{Admission, AtomicBatch, CommitReceipt, Profile, ReadStore, Snapshot, WriterClient};
use se_types::{Read, Result};

impl HistoryPort for ExecutionContext {
    fn run_blocking<'a>(
        &'a self,
        deadline: &'a Deadline,
        work: BlockingWork,
    ) -> PortFuture<'a, ()> {
        Box::pin(self.blocking.run(BlockingClass::Foreground, deadline, work))
    }
    fn snapshot(&self, admission: &Admission, read: ReadPin<'_>) -> Result<()> {
        executor::check_generation(&self.reader, self.generation)?;
        let mut snapshot = self
            .reader
            .snapshot(read_scope(admission))
            .map_err(|e| store_error(&e))?;
        let result = read(&mut snapshot);
        executor::close_read(result, snapshot.close())
    }
    fn append<'a>(
        &'a self,
        batch: AtomicBatch,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, CommitReceipt> {
        Box::pin(append(self, batch, deadline))
    }
    fn owner_profiles(&self) -> Read<Vec<Profile>> {
        match self.custody.get() {
            Some(custody) => match custody.import_profiles() {
                Ok(value) => Read::Present { value },
                Err(error) => Read::Unreadable {
                    source: "active owner profile configuration".into(),
                    reason: error.to_string(),
                    error: Some(Box::new(error.into_body())),
                },
            },
            None => Read::Unknown {
                what:
                    "active owner profile configuration is not available through a native coordinator"
                        .into(),
            },
        }
    }
}

/// The owner operation's only entry. `Kernel::plan` already enforced the
/// owner-only surface; the import repeats generation checks on every job.
pub(super) async fn execute(
    context: ExecutionContext,
    input: se_core::ops::ImportNode,
    admission: Admission,
    kernel: se_core::dispatch::Kernel,
    deadline: &Deadline,
) -> Result<AnyOutput> {
    let context: se_history_import::Context = std::sync::Arc::new(context);
    se_history_import::execute(context, input, admission, kernel, deadline).await
}

/// Import uses the ordinary writer and its existing abandoned-waiter observer.
async fn append(
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
    let record_feed = context.atlas.records.clone();
    let completion = context
        .blocking
        .run_owned(deadline, move || {
            bound.remaining()?;
            let record_write = record_feed.before_scoped_write(&batch.admission.scope)?;
            pending.register(&identity)?;
            match writer.submit(batch) {
                Ok(waiter) => Ok(runtime.spawn(async move {
                    let receipt = waiter.await;
                    if receipt
                        .as_ref()
                        .is_err_and(|e| e.code == se_store::StoreErrorCode::CommitOutcomeUnknown)
                    {
                        record_write.uncertain();
                    } else {
                        drop(record_write);
                    }
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
            let committed = super::CommittedWrite {
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
