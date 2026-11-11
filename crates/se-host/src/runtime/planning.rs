//! The admission read becomes the planning snapshot inside the same worker.
//! Only owned plans leave this module; no SQL handle crosses an await.
use super::{executor, *};
use crate::client::lease::Deadline;
use se_types::{Result, SeError};
use std::sync::Arc;

pub struct PreparedCall(Prepared);
enum Prepared {
    ExpiredAtlasHook,
    Plan(Box<executor::Planned>, Deadline),
}
pub(super) struct Planner {
    atlas: Arc<crate::atlas_runtime::read_port::AtlasOwnerPort>,
    ticket: Result<Option<crate::atlas_runtime::record_fence::RecordFeedTicket>>,
    generation: se_types::Generation,
    status_home: Option<std::path::PathBuf>,
}
impl Planner {
    /// Capture the record fence before opening the store snapshot, preserving
    /// the existing Atlas/store ordering without caching caller authority.
    pub(super) fn new(context: &ExecutionContext) -> Self {
        Self {
            ticket: context.atlas.records.ticket(),
            atlas: Arc::clone(&context.atlas),
            generation: context.generation,
            status_home: context
                .custody
                .get()
                .filter(|custody| custody.prepares_status())
                .map(|_| context.state_directory.clone()),
        }
    }
    pub(super) fn prepare(
        self,
        phase: se_store::ReadPhase,
        call: HostedCall,
        deadline: Deadline,
    ) -> Result<PreparedCall> {
        let selection = (|| {
            if call.admission.generation != self.generation.get() {
                return Err(SeError::invalid(
                    "admitted execution generation",
                    "this exact context's committed generation",
                ));
            }
            let deadline = if let HostedInput::Operation(se_core::ops::AnyOp::AtlasAugment(input)) =
                &call.input
            {
                match input
                    .deadline
                    .and_then(|end| end.checked_duration_since(std::time::Instant::now()))
                    .filter(|remaining| !remaining.is_zero())
                {
                    Some(remaining) => deadline.stage(remaining)?,
                    None => return Ok(None),
                }
            } else {
                deadline
            };
            deadline.remaining()?;
            let needs_atlas = matches!(&call.input, HostedInput::Operation(operation)
                if operation.atlas_options().is_some() || matches!(operation,
                    se_core::ops::AnyOp::AtlasAugment(_) | se_core::ops::AnyOp::Resume(_) | se_core::ops::AnyOp::SessionContext(_)));
            let ticket = if needs_atlas {
                match self.ticket {
                    Ok(ticket) => ticket,
                    Err(error) if matches!(&call.input, HostedInput::Operation(op) if op.atlas_options().is_some()) =>
                    {
                        return Err(error);
                    }
                    Err(_) => None,
                }
            } else {
                None
            };
            Ok(Some((deadline, ticket)))
        })();
        match selection {
            Ok(Some((deadline, ticket))) => executor::plan(
                phase,
                call,
                self.status_home.as_deref(),
                Some((&self.atlas, ticket)),
            )
            .map(|plan| PreparedCall(Prepared::Plan(Box::new(plan), deadline))),
            Ok(None) => {
                executor::close_read(Ok(PreparedCall(Prepared::ExpiredAtlasHook)), phase.close())
            }
            Err(error) => executor::close_read(Err(error), phase.close()),
        }
    }
}
impl PreparedCall {
    pub(super) async fn execute(
        self,
        context: ExecutionContext,
        host_phases: se_core::ops::HostPhaseTimings,
    ) -> Result<ExecutedCall> {
        match self.0 {
            Prepared::Plan(plan, deadline) => {
                executor::finish(context, *plan, deadline, host_phases).await
            }
            Prepared::ExpiredAtlasHook => Ok(ExecutedCall {
                host_phases,
                output: se_core::ops::AtlasHookOutput::default().into(),
                write_timings: None,
                committed: None,
                capture_commits: Vec::new(),
                capture_keys: Vec::new(),
            }),
        }
    }
}
