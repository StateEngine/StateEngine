//! The sole async store bridge. Synchronous planning, submission and continuation
//! run on bounded blocking jobs; only the owned commit completion is awaited.
use super::failure::WriteIdentity;
use super::timings::{self, Mode};
use super::*;
use crate::client::lease::Deadline;
use se_core::{
    admission::read_scope,
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops::AnyOutput,
    ports::{CustodyPlan, Then},
    store_error::store_error,
};
use se_store::{Admission, Snapshot};
use se_types::{Read, Result, SeError};
use std::future::Future;

type Step = OpStep<AnyOutput, Then, CustodyPlan>;
pub(super) struct Planned {
    step: Step,
    observations: Vec<crate::AgentObservationPlan>,
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
        #[cfg(feature = "remote")]
        let mut admitted = admitted;
        if let HostedInput::Operation(operation) = &admitted.input
            && operation.is_remote()
        {
            return super::remote::execute(&context, admitted, &deadline).await;
        }
        #[cfg(feature = "remote")]
        if let Err(error) = super::remote::resume_mail(&context, &admitted, &deadline).await
            && let HostedInput::Operation(operation) = &mut admitted.input
        {
            match operation {
                se_core::ops::AnyOp::Resume(input) => {
                    input.source_failure = Some(error.into_body())
                }
                se_core::ops::AnyOp::SessionContext(input) => {
                    input.source_failure = Some(error.into_body())
                }
                _ => (),
            }
        }
        let reader = context.reads.clone();
        let generation = context.generation;
        let planning_context = context.clone();
        let plan_deadline = deadline.clone();
        let (prepared, planning) =
            timings::blocking(&context.blocking, Mode::Finite, &deadline, move || {
                let planner = super::planning::Planner::new(&planning_context);
                let phase = checked_pooled_phase(&reader, generation)?;
                planner.prepare(phase, admitted, plan_deadline)
            })
            .await?;
        prepared
            .execute(
                context,
                se_core::ops::HostPhaseTimings {
                    planning: Some(planning),
                    ..Default::default()
                },
            )
            .await
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the finish closure keeps every OpStep arm beside the shared read-phase seam; split only if the arm set grows"
)]
pub(super) async fn finish(
    context: ExecutionContext,
    planned: Planned,
    deadline: Deadline,
    mut host_phases: se_core::ops::HostPhaseTimings,
) -> Result<ExecutedCall> {
    let generation = context.generation;
    let Planned {
        step,
        observations,
        kernel,
        admission,
        operation,
        natural_key,
    } = planned;
    match step {
        OpStep::Complete(mut output) => {
            let native = matches!(&output, AnyOutput::ProjectStatus(_))
                .then(|| context.custody.get().cloned())
                .flatten();
            if !observations.is_empty() || native.is_some() {
                let observe_deadline = deadline.clone();
                let command_home = context.state_directory.clone();
                let observed_admission = admission.clone();
                output = context
                    .blocking
                    .run(BlockingClass::Foreground, &deadline, move || {
                        observe_deadline.remaining()?;
                        crate::agent_observation::output::observe(
                            &mut output,
                            observations,
                            observe_deadline.at(),
                            &command_home,
                        )?;
                        if let Some(native) = native {
                            native.observe_native_output(
                                &mut output,
                                &observed_admission,
                                &observe_deadline,
                            )?;
                        }
                        observe_deadline.remaining()?;
                        Ok(output)
                    })
                    .await?;
            }
            if let Some(custody) = context.custody.get() {
                output = custody.observe_output(output, &deadline).await?;
            }
            Ok(ExecutedCall {
                host_phases,
                output,
                write_timings: None,
                committed: None,
                capture_commits: Vec::new(),
                capture_keys: Vec::new(),
            })
        }
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
            let (mut receipt, submission, completion_wait_us) =
                super::submit::measured(&context, batch, &identity, &deadline).await?;
            host_phases.submission = Some(submission);
            host_phases.completion_wait_us = Some(completion_wait_us);
            let committed = CommittedWrite {
                operation: identity.operation.into(),
                key: identity.key.clone(),
                natural_events: identity.natural_events.clone(),
                committed_events: receipt.events.clone(),
            };
            let write_timings = receipt.write_timings.take();
            let finish_deadline = deadline.clone();
            let pool = context.blocking.clone();
            let (output, continuation) =
                timings::blocking(&pool, Mode::Finite, &deadline, move || {
                    let _profile = se_store::phase_trace::Scope::new("readback");
                    finish_deadline.remaining()?;
                    let phase = checked_pooled_phase(&context.reads, generation)?;
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
            host_phases.continuation = Some(continuation);
            Ok(ExecutedCall {
                host_phases,
                output,
                write_timings,
                committed: Some(committed),
                capture_commits: Vec::new(),
                capture_keys: Vec::new(),
            })
        }
        #[cfg(feature = "import")]
        OpStep::Custody(CustodyPlan::ImportNode(input)) => Ok(ExecutedCall {
            host_phases,
            output: super::history_import::execute(context, input, admission, kernel, &deadline)
                .await?,
            write_timings: None,
            committed: None,
            capture_commits: Vec::new(),
            capture_keys: Vec::new(),
        }),
        OpStep::Custody(plan) => match context.custody.get() {
            Some(custody) => Ok(ExecutedCall {
                host_phases,
                output: custody.execute(plan, admission, &deadline).await?,
                write_timings: None,
                committed: None,
                capture_commits: Vec::new(),
                capture_keys: Vec::new(),
            }),
            None => Err(se_core::scope::unreadable(
                "host native custody",
                "the typed native coordinator must resolve this plan before store execution; no transaction or synthetic receipt was produced",
            )),
        },
    }
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn plan(
    phase: se_store::ReadPhase,
    call: HostedCall,
    status_home: Option<&std::path::Path>,
    atlas: Option<(
        &crate::atlas_runtime::read_port::AtlasOwnerPort,
        Option<crate::atlas_runtime::record_fence::RecordFeedTicket>,
    )>,
) -> Result<Planned> {
    let _phase = se_store::phase_trace::Span::new("host_plan");
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
        remote_credential: _,
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
                let context_bytes = match &operation {
                    se_core::ops::AnyOp::SessionContext(input) => Some(input.byte_budget),
                    _ => None,
                };
                match kernel.plan(operation, &mut cx, &terminal)? {
                    OpStep::Complete(mut output)
                        if matches!(
                            output,
                            AnyOutput::Resume(_) | AnyOutput::SessionContext(_)
                        ) =>
                    {
                        if let Some((owner, ticket)) = atlas {
                            crate::atlas_continuity::attach(
                                owner,
                                ticket,
                                cx.read,
                                &admission,
                                &mut output,
                                context_bytes,
                            )?;
                        }
                        Ok(OpStep::Complete(output))
                    }
                    OpStep::Custody(CustodyPlan::ObserveStatus(input)) => match status_home {
                        Some(home) => Ok(OpStep::Complete(super::status::prepare(
                            input, home, &mut cx,
                        )?)),
                        None => Ok(OpStep::Custody(CustodyPlan::ObserveStatus(input))),
                    },
                    OpStep::Custody(CustodyPlan::AtlasAugment(input)) => {
                        let result = atlas.map_or_else(
                            || Ok(se_core::ops::AtlasHookOutput::default()),
                            |(owner, ticket)| {
                                crate::atlas_hooks::owner_augment(
                                    owner, ticket, &input, cx.read, &admission,
                                )
                            },
                        );
                        Ok(OpStep::Complete(result?.into()))
                    }
                    OpStep::Custody(CustodyPlan::AtlasRead(request)) => {
                        let (owner, ticket) = atlas.ok_or_else(|| se_core::scope::unreadable("Atlas owner reader", "the admitted runtime must supply its existing controller read port"))?;
                        Ok(OpStep::Complete(crate::atlas_queries::owner_read(
                            owner,
                            ticket,
                            &request,
                            cx.read,
                            &admission,
                            super::start::now_unix_micros()? / 1000,
                        )?))
                    }
                    step => Ok(step),
                }
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
    let result = result.and_then(|step| {
        let observations = match &step {
            OpStep::Complete(output) => {
                crate::agent_observation::output::prepare(&admission.scope, output, &mut read)?
            }
            _ => Vec::new(),
        };
        Ok((step, observations))
    });
    let (step, observations) = close_read(result, read.close())?;
    Ok(Planned {
        step,
        observations,
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
#[cfg(all(feature = "listener", feature = "import"))]
pub(crate) fn check_generation(
    reader: &se_store::SqliteReader,
    expected: se_types::Generation,
) -> Result<()> {
    let phase = checked_phase(reader, expected)?;
    close_read(Ok(()), phase.close())
}
#[cfg(any(
    test,
    feature = "secode",
    all(feature = "listener", feature = "import")
))]
pub(super) fn checked_phase(
    reader: &se_store::SqliteReader,
    expected: se_types::Generation,
) -> Result<se_store::ReadPhase> {
    let phase = reader.read_phase().map_err(|error| store_error(&error))?;
    generation_phase(phase, expected)
}
pub(crate) fn checked_pooled_phase(
    reader: &se_store::ReadPhasePool,
    expected: se_types::Generation,
) -> Result<se_store::ReadPhase> {
    let phase = reader.read_phase().map_err(|error| store_error(&error))?;
    generation_phase(phase, expected)
}
fn generation_phase(
    phase: se_store::ReadPhase,
    expected: se_types::Generation,
) -> Result<se_store::ReadPhase> {
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

#[cfg(test)]
#[path = "read_phase_tests.rs"]
pub(crate) mod read_phase_tests;
