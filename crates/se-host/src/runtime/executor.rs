//! The sole async store bridge. Synchronous planning, submission and continuation
//! run on bounded blocking jobs; only the owned commit completion is awaited.
use super::*;
use se_core::{
    admission::read_scope,
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops::AnyOutput,
    ports::{CustodyPlan, Then},
    store_error::{store_error, write_error},
};
use se_store::{Admission, ReadStore, Snapshot, WriterClient};
use se_types::{Read, Result, SeError};
use std::future::Future;

type Step = OpStep<AnyOutput, Then, CustodyPlan>;
struct Planned {
    step: Step,
    kernel: Kernel,
    admission: Admission,
    operation: &'static str,
}
/// The explicit bound prevents a later snapshot/SQL-handle change from silently
/// making the host's concrete execution future local to a worker thread.
#[expect(
    clippy::manual_async_fn,
    reason = "The public handoff checks its future is Send."
)]
pub fn execute(
    context: ExecutionContext,
    call: ExecutionCall,
) -> impl Future<Output = Result<ExecutedCall>> + Send {
    async move {
        let ExecutionCall { admitted, deadline } = call;
        let reader = std::sync::Arc::clone(&context.reader);
        let generation = context.generation;
        if admitted.admission.generation != generation.get() {
            return Err(SeError::invalid(
                "admitted execution generation",
                "this exact context's committed generation",
            ));
        }
        let plan_deadline = deadline.clone();
        let planned = context
            .blocking
            .run(BlockingClass::Foreground, &deadline, move || {
                plan_deadline.remaining()?;
                check_generation(&reader, generation)?;
                plan(&reader, admitted)
            })
            .await?;
        let Planned {
            step,
            kernel,
            admission,
            operation,
        } = planned;
        match step {
            OpStep::Complete(output) => Ok(ExecutedCall {
                output,
                write_timings: None,
            }),
            OpStep::Commit { batch, then } => {
                let identity = WriteIdentity {
                    operation,
                    key: batch.request.as_ref().map(|request| request.key.clone()),
                    natural_events: if batch.request.is_none() {
                        batch
                            .events
                            .iter()
                            .map(|event| event.header.event.clone())
                            .collect()
                    } else {
                        Vec::new()
                    },
                };
                // submit performs finite bounded queue admission and serialization.
                // Preserve the returned waiter even if native work uses the final
                // part of the budget; the original request identity is unchanged.
                let writer = context.writer.clone();
                let submit_deadline = deadline.clone();
                let submitted = identity.clone();
                let completion = context
                    .blocking
                    .run_owned(&deadline, move || {
                        submit_deadline.remaining()?;
                        writer
                            .submit(batch)
                            .map_err(|error| submitted.store_error(&error))
                    })
                    .await?;
                // Neither a worker permit nor a read transaction survives here.
                // Timeout/cancel never cancels an accepted store transaction; the
                // caller must resolve/retry its original operation/natural key.
                let mut receipt = super::pool::within(&deadline, completion)
                    .await
                    .map_err(|error| identity.wait_error(error))?
                    .map_err(|error| identity.store_error(&error))?;
                let write_timings = receipt.write_timings.take();
                let finish_deadline = deadline.clone();
                let output = context
                    .blocking
                    .run(BlockingClass::Foreground, &deadline, move || {
                        finish_deadline.remaining()?;
                        check_generation(&context.reader, generation)?;
                        let mut read = context
                            .reader
                            .snapshot(read_scope(&admission))
                            .map_err(|error| store_error(&error))?;
                        let result = kernel.committed(
                            then,
                            receipt,
                            &mut Cx {
                                read: &mut read,
                                admission: &admission,
                            },
                        );
                        close_read(result, read.close())
                    })
                    // A durable receipt has not yet reached the caller. Any
                    // continuation failure still needs its original retry identity.
                    .await
                    .map_err(|error| identity.wait_error(error))?;
                Ok(ExecutedCall {
                    output,
                    write_timings,
                })
            }
            OpStep::Custody(_) => Err(se_core::scope::unreadable(
                "host native custody",
                "the typed native coordinator must resolve this plan before store execution; no transaction or synthetic receipt was produced",
            )),
        }
    }
}
fn plan(reader: &se_store::SqliteReader, call: HostedCall) -> Result<Planned> {
    let operation = match &call.input {
        HostedInput::Operation(operation) => operation.meta().name,
        HostedInput::Capture(_) => "hook.claude",
    };
    let HostedCall {
        input,
        kernel,
        admission,
        terminal,
        selections,
    } = call;
    let mut read = reader
        .snapshot(read_scope(&admission))
        .map_err(|error| store_error(&error))?;
    let result = (|| {
        let mut cx = Cx {
            read: &mut read,
            admission: &admission,
        };
        match input {
            HostedInput::Operation(mut operation) => {
                if let Some(selections) = selections {
                    selections.apply(&mut operation, &mut cx)?;
                }
                kernel.plan(operation, &mut cx, &terminal)
            }
            HostedInput::Capture(capture) => {
                if selections.is_some() {
                    return Err(SeError::invalid(
                        "capture routing",
                        "no CLI selection metadata on a trusted capture",
                    ));
                }
                Ok(
                    match se_core::ops::hook::plan(capture.request, capture.facts, &mut cx)? {
                        OpStep::Complete(output) => OpStep::Complete(output),
                        OpStep::Commit { batch, then } => OpStep::Commit { batch, then },
                        OpStep::Custody(never) => match never {},
                    },
                )
            }
        }
    })();
    let step = close_read(result, read.close())?;
    Ok(Planned {
        step,
        kernel,
        admission,
        operation,
    })
}
#[derive(Clone)]
struct WriteIdentity {
    operation: &'static str,
    key: Option<se_types::IdempotencyKey>,
    natural_events: Vec<se_types::EventId>,
}
impl WriteIdentity {
    fn store_error(&self, error: &se_store::StoreError) -> SeError {
        write_error(
            error,
            self.operation,
            self.key.as_ref(),
            &self.natural_events,
        )
    }
    fn wait_error(&self, cause: SeError) -> SeError {
        SeError::new(se_types::Detail::CommitOutcomeUnknown(
            se_types::details::CommitOutcomeUnknown {
                operation: self.operation.into(),
                key: self.key.as_ref().map(ToString::to_string),
                natural_events: self.natural_events.clone(),
            },
        ))
        .with_cause(cause)
    }
}
pub(crate) fn close_read<T>(result: Result<T>, closed: se_store::StoreResult<()>) -> Result<T> {
    match (result, closed) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(store_error(&error)),
        (Err(original), Err(error)) => Err(original.with_cause(error)),
    }
}
pub(crate) fn check_generation(
    reader: &se_store::SqliteReader,
    expected: se_types::Generation,
) -> Result<()> {
    match reader
        .runtime_owner()
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } if value.generation == expected => Ok(()),
        Read::Present { .. } => Err(SeError::invalid(
            "execution generation",
            "the same committed runtime owner generation",
        )),
        Read::Absent { checked } => Err(se_core::scope::unreadable(
            "execution generation",
            &format!("runtime owner absent: {checked}"),
        )),
        Read::Unreadable { source, reason, .. } => {
            Err(se_core::scope::unreadable(&source, &reason))
        }
        Read::Unknown { what } => Err(se_core::scope::unreadable("execution generation", &what)),
    }
}
