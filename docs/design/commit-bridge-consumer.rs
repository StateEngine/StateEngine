//! Compile-only consumer of the frozen S-R1 bridge, not a runtime or test.
//! No CoreOps/Store implementation or default/fake receipt is supplied.
use se_core::commit::{
    CoreOps, Cx, MessageSend, MessageSendOutput, OpStep, WorkingStateSet, WorkingStateSetOutput,
};
use se_store::{DirectStore, ReadScope, ReadStore, RuntimeLease, StoreError, WriterClient};
use se_types::SeError;
use std::future::Future;

#[derive(Debug)]
pub enum ConsumerError {
    Core(SeError),
    Store(Box<StoreError>),
}

/// Plan synchronously; close its actual Snapshot before constructing the Send future.
/// WriterClient is obtained through HostStore::start_writer -> WriterOwner::client.
pub fn message_via_host<'a, K: CoreOps, R: ReadStore + Sync, W: WriterClient>(
    core: &'a K,
    reader: &'a R,
    scope: ReadScope,
    input: MessageSend,
    writer: &'a W,
) -> impl Future<Output = Result<MessageSendOutput, ConsumerError>> + Send + 'a {
    let step = match reader.snapshot(scope.clone()) {
        Ok(mut read) => {
            let mut cx = Cx {
                read: &mut read,
                admission: &scope.admission,
            };
            core.message_send(input, &mut cx)
                .map_err(ConsumerError::Core)
        }
        Err(error) => Err(ConsumerError::Store(error)),
    };
    async move {
        match step? {
            OpStep::Complete(output) => Ok(output),
            OpStep::Commit { batch, then } => {
                let completion = writer.submit(batch).map_err(ConsumerError::Store)?;
                let receipt = completion.await.map_err(ConsumerError::Store)?;
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

/// Plan synchronously; close its actual Snapshot before constructing the Send future.
/// WriterClient is obtained through HostStore::start_writer -> WriterOwner::client.
pub fn working_state_via_host<'a, K: CoreOps, R: ReadStore + Sync, W: WriterClient>(
    core: &'a K,
    reader: &'a R,
    scope: ReadScope,
    input: WorkingStateSet,
    writer: &'a W,
) -> impl Future<Output = Result<WorkingStateSetOutput, ConsumerError>> + Send + 'a {
    let step = match reader.snapshot(scope.clone()) {
        Ok(mut read) => {
            let mut cx = Cx {
                read: &mut read,
                admission: &scope.admission,
            };
            core.working_state_set(input, &mut cx)
                .map_err(ConsumerError::Core)
        }
        Err(error) => Err(ConsumerError::Store(error)),
    };
    async move {
        match step? {
            OpStep::Complete(output) => Ok(output),
            OpStep::Commit { batch, then } => {
                let completion = writer.submit(batch).map_err(ConsumerError::Store)?;
                let receipt = completion.await.map_err(ConsumerError::Store)?;
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
