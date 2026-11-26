//! Read-only continuity, mailbox, history, identity, working-state and Atlas planning.
use super::{Kernel, PlanStep};
use crate::{
    commit::{Cx, OpStep},
    scope,
};
use se_store::Snapshot;
use se_types::Result;

pub(super) fn plan_atlas_read(read: crate::ops::AtlasRead) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::AtlasRead(
        Box::new(read),
    )))
}

pub(super) fn plan_resume<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::Resume,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::continuity::resume_at_home(
            input,
            kernel.observed_at()?,
            kernel.command_home.as_deref(),
            cx,
        )?
        .into(),
    ))
}

pub(super) fn plan_session_context<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::SessionContextRequest,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::continuity::context_at_home(
            input,
            kernel.observed_at()?,
            kernel.command_home.as_deref(),
            cx,
        )?
        .into(),
    ))
}

pub(super) fn plan_working_state_get<R: Snapshot>(
    input: crate::ops::WorkingStateGet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::receipt::working_state_get(
            scope::working_agent(
                cx.admission,
                input.owner_agent.as_ref(),
                "working_state.get",
            )?,
            cx,
        )?
        .into(),
    ))
}

pub(super) fn plan_identity_whoami<R: Snapshot>(
    input: crate::ops::IdentityWhoami,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::identity::whoami(input, cx)?.into(),
    ))
}

pub(super) fn plan_history_list<R: Snapshot>(
    input: crate::ops::HistoryList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::history::list(input, cx)?.into(),
    ))
}

pub(super) fn plan_history_search<R: Snapshot>(
    input: crate::ops::HistorySearch,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::history::search(input, cx)?.into(),
    ))
}

pub(super) fn plan_message_list<R: Snapshot>(
    input: crate::ops::MessageList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::message::list(input, cx)?.into(),
    ))
}

pub(super) fn plan_message_inbox<R: Snapshot>(
    input: crate::ops::MessageInbox,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(crate::ops::inbox::read(input, cx)?.into()))
}
