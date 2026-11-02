//! The sole async store bridge. Synchronous planning, submission and continuation
//! run on bounded blocking jobs; only the owned commit completion is awaited.
use super::failure::WriteIdentity;
use super::*;
use se_core::{
    admission::read_scope,
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops::AnyOutput,
    ports::{CustodyPlan, Then},
    store_error::store_error,
};
use se_store::{Admission, Snapshot, WriterClient};
use se_types::{Read, Result, SeError};
use std::future::Future;

type Step = OpStep<AnyOutput, Then, CustodyPlan>;
struct Planned {
    step: Step,
    kernel: Kernel,
    admission: Admission,
    operation: &'static str,
    natural_key: Option<String>,
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
                let phase = checked_phase(&reader, generation)?;
                plan(phase, admitted)
            })
            .await?;
        let Planned {
            step,
            kernel,
            admission,
            operation,
            natural_key,
        } = planned;
        match step {
            OpStep::Complete(output) => Ok(ExecutedCall {
                output,
                write_timings: None,
                committed: None,
                capture_commits: Vec::new(),
                capture_keys: Vec::new(),
            }),
            OpStep::Commit { batch, then } => {
                let identity = WriteIdentity {
                    operation,
                    natural_key,
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
                let pending = context.pending_writes.clone();
                let runtime = context.blocking.handle();
                let completion = context
                    .blocking
                    .run_owned(&deadline, move || {
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
                                            if error.code
                                                == se_store::StoreErrorCode::CommitOutcomeUnknown =>
                                        {
                                            Ok(())
                                        }
                                        Err(_) => pending.failed_attempt(&submitted),
                                    };
                                    (receipt, settled)
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
                let (receipt, settled) = super::pool::within(&deadline, completion)
                    .await
                    .map_err(|error| identity.wait_error(error))?
                    .map_err(|error| {
                        identity.wait_error(se_core::scope::unreadable(
                            "write completion observer",
                            &error.to_string(),
                        ))
                    })?;
                let mut receipt = match receipt {
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
                let write_timings = receipt.write_timings.take();
                let finish_deadline = deadline.clone();
                let output = context
                    .blocking
                    .run(BlockingClass::Foreground, &deadline, move || {
                        finish_deadline.remaining()?;
                        let phase = checked_phase(&context.reader, generation)?;
                        let mut read = phase
                            .into_snapshot(read_scope(&admission))
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
                    .await
                    .map_err(|error| committed.response_error(error))?;
                Ok(ExecutedCall {
                    output,
                    write_timings,
                    committed: Some(committed),
                    capture_commits: Vec::new(),
                    capture_keys: Vec::new(),
                })
            }
            OpStep::Custody(_) => Err(se_core::scope::unreadable(
                "host native custody",
                "the typed native coordinator must resolve this plan before store execution; no transaction or synthetic receipt was produced",
            )),
        }
    }
}
fn plan(phase: se_store::ReadPhase, call: HostedCall) -> Result<Planned> {
    let natural_key = match &call.input {
        HostedInput::Capture(capture) => Some(format!(
            "session={:?}, provider={:?}, conversation={}, turn={}",
            call.admission.session,
            capture.request.provider,
            capture.request.conversation,
            capture.request.vendor_turn
        )),
        _ => None,
    };
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
    let mut read = phase
        .into_snapshot(read_scope(&admission))
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
        natural_key,
    })
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
    let phase = checked_phase(reader, expected)?;
    close_read(Ok(()), phase.close())
}
fn checked_phase(
    reader: &se_store::SqliteReader,
    expected: se_types::Generation,
) -> Result<se_store::ReadPhase> {
    let phase = reader.read_phase().map_err(|error| store_error(&error))?;
    let result = phase
        .runtime_owner()
        .map_err(|error| store_error(&error))
        .and_then(|owner| match owner {
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
            Read::Unknown { what } => {
                Err(se_core::scope::unreadable("execution generation", &what))
            }
        });
    match result {
        Ok(()) => Ok(phase),
        Err(error) => close_read(Err(error), phase.close()),
    }
}
