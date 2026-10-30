//! Compile-only consumer of the frozen S-R1 bridge, not a runtime or test.
//! No CoreOps/Store implementation or default/fake receipt is supplied.
//! Consumer-only Tokio features are rt + sync; core itself remains synchronous.
use se_core::commit::{
    CoreOps, Cx, MessageSend, MessageSendOutput, OpStep, WorkingStateSet, WorkingStateSetOutput,
};
use se_store::{DirectStore, ReadScope, ReadStore, RuntimeLease, StoreError, WriterClient};
use se_types::SeError;
use std::{future::Future, sync::Arc};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::JoinError;

#[derive(Debug)]
pub enum ConsumerError {
    Core(SeError),
    Store(Box<StoreError>),
    Capacity(TryAcquireError),
    Worker(JoinError),
}

/// Owned reader/core enter bounded blocking jobs; no SQLite read runs on the executor.
/// WriterClient comes from HostStore::start_writer -> WriterOwner::client.
/// The host supplies its Handle and shared two-job semaphore; no ambient runtime.
#[expect(
    clippy::manual_async_fn,
    reason = "The explicit future bound checks Send at this consumer seam."
)]
pub fn message_via_host<
    'a,
    K: CoreOps + 'static,
    R: ReadStore + Send + Sync + 'static,
    W: WriterClient,
>(
    core: Arc<K>,
    reader: Arc<R>,
    scope: ReadScope,
    input: MessageSend,
    writer: &'a W,
    blocking_slots: Arc<Semaphore>,
    runtime: Handle,
) -> impl Future<Output = Result<MessageSendOutput, ConsumerError>> + Send + 'a {
    async move {
        // Admission bounds queued plus running blocking jobs, without a polling loop.
        let permit = blocking_slots
            .clone()
            .try_acquire_owned()
            .map_err(ConsumerError::Capacity)?;
        let planning_core = core.clone();
        let planning_reader = reader.clone();
        let planning_scope = scope.clone();
        let step = runtime
            .spawn_blocking(move || {
                let _permit = permit;
                let mut read = planning_reader
                    .snapshot(planning_scope.clone())
                    .map_err(ConsumerError::Store)?;
                let mut cx = Cx {
                    read: &mut read,
                    admission: &planning_scope.admission,
                };
                planning_core
                    .message_send(input, &mut cx)
                    .map_err(ConsumerError::Core)
            })
            .await
            .map_err(ConsumerError::Worker)??;
        match step {
            OpStep::Complete(output) => Ok(output),
            OpStep::Commit { batch, then } => {
                let completion = writer.submit(batch).map_err(ConsumerError::Store)?;
                let receipt = completion.await.map_err(ConsumerError::Store)?;
                let permit = blocking_slots
                    .try_acquire_owned()
                    .map_err(ConsumerError::Capacity)?;
                runtime
                    .spawn_blocking(move || {
                        let _permit = permit;
                        let mut read = reader
                            .snapshot(scope.clone())
                            .map_err(ConsumerError::Store)?;
                        let mut cx = Cx {
                            read: &mut read,
                            admission: &scope.admission,
                        };
                        core.message_committed(then, receipt, &mut cx)
                            .map_err(ConsumerError::Core)
                    })
                    .await
                    .map_err(ConsumerError::Worker)?
            }
            OpStep::Custody(never) => match never {},
        }
    }
}

/// CLI-only synchronous DirectStore::append, same AtomicBatch and CommitReceipt.
pub fn message_via_direct<K: CoreOps, R: ReadStore, D: DirectStore>(
    core: &K,
    reader: &R,
    scope: ReadScope,
    input: MessageSend,
    direct: &mut D,
    lease: &dyn RuntimeLease,
) -> Result<MessageSendOutput, ConsumerError> {
    let step = {
        let mut read = reader
            .snapshot(scope.clone())
            .map_err(ConsumerError::Store)?;
        let mut cx = Cx {
            read: &mut read,
            admission: &scope.admission,
        };
        core.message_send(input, &mut cx)
            .map_err(ConsumerError::Core)?
    };
    match step {
        OpStep::Complete(output) => Ok(output),
        OpStep::Commit { batch, then } => {
            let receipt = direct.append(batch, lease).map_err(ConsumerError::Store)?;
            let mut read = reader
                .snapshot(scope.clone())
                .map_err(ConsumerError::Store)?;
            let mut cx = Cx {
                read: &mut read,
                admission: &scope.admission,
            };
            core.message_committed(then, receipt, &mut cx)
                .map_err(ConsumerError::Core)
        }
        OpStep::Custody(never) => match never {},
    }
}

/// Owned reader/core enter bounded blocking jobs; no SQLite read runs on the executor.
/// WriterClient comes from HostStore::start_writer -> WriterOwner::client.
/// The host supplies its Handle and shared two-job semaphore; no ambient runtime.
#[expect(
    clippy::manual_async_fn,
    reason = "The explicit future bound checks Send at this consumer seam."
)]
pub fn working_state_via_host<
    'a,
    K: CoreOps + 'static,
    R: ReadStore + Send + Sync + 'static,
    W: WriterClient,
>(
    core: Arc<K>,
    reader: Arc<R>,
    scope: ReadScope,
    input: WorkingStateSet,
    writer: &'a W,
    blocking_slots: Arc<Semaphore>,
    runtime: Handle,
) -> impl Future<Output = Result<WorkingStateSetOutput, ConsumerError>> + Send + 'a {
    async move {
        // Admission bounds queued plus running blocking jobs, without a polling loop.
        let permit = blocking_slots
            .clone()
            .try_acquire_owned()
            .map_err(ConsumerError::Capacity)?;
        let planning_core = core.clone();
        let planning_reader = reader.clone();
        let planning_scope = scope.clone();
        let step = runtime
            .spawn_blocking(move || {
                let _permit = permit;
                let mut read = planning_reader
                    .snapshot(planning_scope.clone())
                    .map_err(ConsumerError::Store)?;
                let mut cx = Cx {
                    read: &mut read,
                    admission: &planning_scope.admission,
                };
                planning_core
                    .working_state_set(input, &mut cx)
                    .map_err(ConsumerError::Core)
            })
            .await
            .map_err(ConsumerError::Worker)??;
        match step {
            OpStep::Complete(output) => Ok(output),
            OpStep::Commit { batch, then } => {
                let completion = writer.submit(batch).map_err(ConsumerError::Store)?;
                let receipt = completion.await.map_err(ConsumerError::Store)?;
                let permit = blocking_slots
                    .try_acquire_owned()
                    .map_err(ConsumerError::Capacity)?;
                runtime
                    .spawn_blocking(move || {
                        let _permit = permit;
                        let mut read = reader
                            .snapshot(scope.clone())
                            .map_err(ConsumerError::Store)?;
                        let mut cx = Cx {
                            read: &mut read,
                            admission: &scope.admission,
                        };
                        core.working_state_committed(then, receipt, &mut cx)
                            .map_err(ConsumerError::Core)
                    })
                    .await
                    .map_err(ConsumerError::Worker)?
            }
            OpStep::Custody(never) => match never {},
        }
    }
}

/// CLI-only synchronous DirectStore::append, same AtomicBatch and CommitReceipt.
pub fn working_state_via_direct<K: CoreOps, R: ReadStore, D: DirectStore>(
    core: &K,
    reader: &R,
    scope: ReadScope,
    input: WorkingStateSet,
    direct: &mut D,
    lease: &dyn RuntimeLease,
) -> Result<WorkingStateSetOutput, ConsumerError> {
    let step = {
        let mut read = reader
            .snapshot(scope.clone())
            .map_err(ConsumerError::Store)?;
        let mut cx = Cx {
            read: &mut read,
            admission: &scope.admission,
        };
        core.working_state_set(input, &mut cx)
            .map_err(ConsumerError::Core)?
    };
    match step {
        OpStep::Complete(output) => Ok(output),
        OpStep::Commit { batch, then } => {
            let receipt = direct.append(batch, lease).map_err(ConsumerError::Store)?;
            let mut read = reader
                .snapshot(scope.clone())
                .map_err(ConsumerError::Store)?;
            let mut cx = Cx {
                read: &mut read,
                admission: &scope.admission,
            };
            core.working_state_committed(then, receipt, &mut cx)
                .map_err(ConsumerError::Core)
        }
        OpStep::Custody(never) => match never {},
    }
}
