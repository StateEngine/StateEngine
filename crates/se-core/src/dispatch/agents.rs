//! Agent lifecycle, roster, captain, assignment, project and configuration planning.
use super::{Kernel, PlanStep};
use crate::{
    commit::{Cx, OpStep},
    scope,
};
use se_store::Snapshot;
use se_types::{Result, SeError};

pub(super) fn plan_agent_list<R: Snapshot>(
    input: crate::ops::AgentList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::listing::agents(input, cx)?.into(),
    ))
}

pub(super) fn plan_agent_launch<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::AgentLaunch,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        scope::unreadable(
            "launch configuration",
            "adapter-resolved ConfigFile is not bound",
        )
    })?;
    Ok(OpStep::Custody(crate::ports::CustodyPlan::Launch(
        Box::new(crate::ops::process_plan::launch(
            kernel,
            input,
            configuration,
            cx,
        )?),
    )))
}

pub(super) fn plan_agent_stop<R: Snapshot>(
    input: crate::ops::AgentStop,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::Stop(Box::new(
        crate::ops::stop_plan::plan(input, cx)?,
    ))))
}

pub(super) fn plan_agent_wake<R: Snapshot>(
    input: crate::ops::AgentWake,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::AgentWake(
        crate::ops::agent_wake::plan(input, cx)?,
    )))
}

pub(super) fn plan_project_remove<R: Snapshot>(
    input: crate::ops::ProjectRemove,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::Remove(
        Box::new(crate::ops::project_remove::plan(input, cx)?),
    )))
}

pub(super) fn plan_agent_show<R: Snapshot>(
    input: crate::ops::AgentShow,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::agent_status::show(input, cx)?.into(),
    ))
}

pub(super) fn plan_assignment_list<R: Snapshot>(
    input: crate::ops::AssignmentList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::assignment::list(input, cx)?.into(),
    ))
}

pub(super) fn plan_captain_set<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::CaptainSet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    crate::ops::captain::step(kernel, Some(input.captain), input.idempotency_key, cx)
}

pub(super) fn plan_captain_clear<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::CaptainClear,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    crate::ops::captain::step(kernel, None, input.idempotency_key, cx)
}

pub(super) fn plan_config_get<R: Snapshot>(
    input: crate::ops::ConfigGet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::agent_config::get(input, cx)?.into(),
    ))
}

pub(super) fn plan_config_set<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::ConfigSet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        scope::unreadable(
            "saved agent configuration",
            "adapter-resolved ConfigFile must be bound using Kernel::with_configuration",
        )
    })?;
    let (batch, then) = crate::ops::agent_config::set(kernel, input, configuration, cx)?;
    Ok(OpStep::Commit {
        batch,
        then: crate::ports::Then::AgentConfig(then),
    })
}

pub(super) fn plan_config_list(kernel: &Kernel, input: crate::ops::ConfigList) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        scope::unreadable(
            "configuration",
            "adapter-resolved ConfigFile must be bound using Kernel::with_configuration",
        )
    })?;
    Ok(OpStep::Complete(
        crate::ops::config_listing::list(configuration, kernel.config_origin.as_deref(), input)?
            .into(),
    ))
}

pub(super) fn plan_agent_create<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::AgentCreate,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        SeError::new(se_types::Detail::Internal(se_types::details::Internal {
            report_id: "agent-configuration-not-bound".into(),
            location: "Kernel::with_configuration".into(),
        }))
    })?;
    let (batch, then) = crate::ops::agent::create(kernel, input, configuration, cx)?;
    Ok(OpStep::Commit {
        batch,
        then: crate::ports::Then::AgentCreate(then),
    })
}

pub(super) fn plan_agent_rename<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::AgentRename,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let (batch, then) = crate::ops::agent::rename(kernel, input, cx)?;
    Ok(OpStep::Commit {
        batch,
        then: crate::ports::Then::AgentRename(then),
    })
}
