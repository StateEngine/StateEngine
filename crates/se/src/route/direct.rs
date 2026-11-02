//! One synchronous direct route; the caller owns the shared OS lease and verified authority.
use se_core::{
    admission::{HumanTerminal, read_scope},
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops::{AnyOp, AnyOutput},
    ports::{CustodyPlan, Then},
    store_error::{store_error, write_error},
};
use se_store::{Admission, DirectStore, ReadStore, RuntimeLease, Snapshot};
use se_types::{Detail, EventId, IdempotencyKey, Result, SeError, details};

pub enum Outcome {
    Complete(AnyOutput),
    Committed {
        output: AnyOutput,
        key: Option<IdempotencyKey>,
        natural_events: Vec<EventId>,
        events: Vec<EventId>,
    },
    Custody(CustodyPlan),
}
/// A custody result carries no store read lease. The caller must release its
/// direct shared runtime lease before activating or forwarding to a host.
pub fn execute<S: DirectStore>(
    store: &mut S,
    lease: &dyn RuntimeLease,
    admission: &Admission,
    terminal: &HumanTerminal,
    kernel: &Kernel,
    op: AnyOp,
    selections: &se_core::ops::CliSelections,
) -> Result<Outcome> {
    let operation = op.meta().name;
    let step = plan(store, admission, terminal, kernel, op, selections)?;
    match step {
        OpStep::Complete(output) => Ok(Outcome::Complete(output)),
        OpStep::Custody(plan) => Ok(Outcome::Custody(plan)),
        OpStep::Commit { batch, then } => {
            let key = batch.request.as_ref().map(|request| request.key.clone());
            let natural_events = if key.is_none() {
                batch
                    .events
                    .iter()
                    .map(|event| event.header.event.clone())
                    .collect()
            } else {
                Vec::new()
            };
            let receipt = store
                .append(batch, lease)
                .map_err(|error| write_error(&error, operation, key.as_ref(), &natural_events))?;
            let committed_events = receipt.events.clone();
            let continuation = (|| {
                let mut snapshot = store
                    .snapshot(read_scope(admission))
                    .map_err(|e| store_error(&e))?;
                let output = kernel.committed(
                    then,
                    receipt,
                    &mut Cx {
                        read: &mut snapshot,
                        admission,
                    },
                );
                let closed = snapshot.close().map_err(|e| store_error(&e));
                match output {
                    Ok(output) => {
                        closed?;
                        Ok(output)
                    }
                    Err(error) => Err(match closed {
                        Ok(()) => error,
                        Err(close) => error.with_cause(close),
                    }),
                }
            })();
            continuation
                .map(|output| Outcome::Committed {
                    output,
                    key: key.clone(),
                    natural_events: natural_events.clone(),
                    events: committed_events.clone(),
                })
                .map_err(|error| {
                    committed_failure(
                        operation,
                        key.as_ref(),
                        &natural_events,
                        &committed_events,
                        error,
                    )
                })
        }
    }
}

/// Current-schema WAL reads use an admitted finite Snapshot while the host may
/// retain its exclusive writer lease. This path cannot append or start a writer.
pub fn read<S: ReadStore>(
    store: &S,
    admission: &Admission,
    terminal: &HumanTerminal,
    op: AnyOp,
    selections: &se_core::ops::CliSelections,
) -> Result<Outcome> {
    if op.meta().effect != se_core::registry::Effect::Read {
        return Err(se_types::SeError::invalid(
            "direct read route",
            "a registered read operation",
        ));
    }
    match plan(
        store,
        admission,
        terminal,
        &Kernel::read_only_at(se_types::UnixMicros::new(
            u64::try_from(super::execute::now_us()?).map_err(|_| {
                SeError::invalid("read observation clock", "nonnegative Unix microseconds")
            })?,
        )?),
        op,
        selections,
    )? {
        OpStep::Complete(output) => Ok(Outcome::Complete(output)),
        OpStep::Custody(plan) => Ok(Outcome::Custody(plan)),
        OpStep::Commit { .. } => Err(se_types::SeError::invalid(
            "direct read plan",
            "a read without a commit step",
        )),
    }
}
fn plan<S: ReadStore>(
    store: &S,
    admission: &Admission,
    terminal: &HumanTerminal,
    kernel: &Kernel,
    mut op: AnyOp,
    selections: &se_core::ops::CliSelections,
) -> Result<OpStep<AnyOutput, Then, CustodyPlan>> {
    let mut snapshot = store
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let selected = selections.apply(
        &mut op,
        &mut Cx {
            read: &mut snapshot,
            admission,
        },
    );
    let planned = selected.and_then(|()| {
        kernel.plan(
            op,
            &mut Cx {
                read: &mut snapshot,
                admission,
            },
            terminal,
        )
    });
    let closed = snapshot.close().map_err(|e| store_error(&e));
    let step = match planned {
        Ok(step) => {
            closed?;
            step
        }
        Err(error) => {
            return Err(match closed {
                Ok(()) => error,
                Err(close) => error.with_cause(close),
            });
        }
    };
    Ok(step)
}

/// A received append receipt is definitive even if later readback/cleanup fails.
pub fn committed_failure(
    operation: &str,
    key: Option<&IdempotencyKey>,
    natural_events: &[EventId],
    committed_events: &[EventId],
    error: SeError,
) -> SeError {
    SeError::new(Detail::CommittedResponseUnavailable(
        details::CommittedResponseUnavailable {
            operation: operation.into(),
            key: key.map(ToString::to_string),
            natural_events: natural_events.to_vec().into_boxed_slice(),
            committed_events: committed_events.to_vec().into_boxed_slice(),
            reason: error.body.message().into(),
        },
    ))
    .with_cause(error)
}
