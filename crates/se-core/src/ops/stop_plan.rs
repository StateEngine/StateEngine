//! Finite owner/self/creator stop selection. Cross-project owner work returns
//! only registered project references; the host opens each admitted project
//! snapshot separately, never promotes an agent to an owner.
use super::{AgentStop, agent_stop::StopTarget, inputs::Validate, process_plan};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, ControlTarget, EventBody, ReadBudget, Scope, Snapshot};
use se_types::{AgentId, Named, PageRequest, ProjectId, Result, SeError};
use std::{num::NonZeroU32, time::Duration};
#[derive(Clone)]
pub struct ControlAgent {
    pub target: StopTarget,
    pub control: ControlTarget,
}
pub struct StopPlan {
    pub input: AgentStop,
    pub projects: Vec<Named<ProjectId>>,
    pub targets: Vec<ControlAgent>,
}
fn budget(after: Option<se_types::Cursor>) -> Result<ReadBudget> {
    Ok(ReadBudget {
        page: PageRequest {
            after,
            limit: NonZeroU32::new(100)
                .ok_or_else(|| SeError::invalid("control page", "positive limit"))?,
            max_bytes: NonZeroU32::new(1024 * 1024)
                .ok_or_else(|| SeError::invalid("control page", "positive bytes"))?,
        },
        deadline: Duration::from_millis(250),
    })
}
pub fn projects<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<Vec<Named<ProjectId>>> {
    if let Scope::Project(id) = &cx.admission.scope {
        let project = scope::require_present(
            cx.read.project(id.clone()).map_err(|e| store_error(&e))?,
            "stop project",
            "Select an initialized project.",
        )?;
        return Ok(vec![project_name(&project.current.body)?]);
    }
    if !matches!(cx.admission.actor, Actor::Human(_)) {
        return Err(SeError::invalid(
            "all-project control",
            "the verified owner",
        ));
    }
    let mut result = Vec::new();
    let mut after = None;
    for _ in 0..64 {
        let page = cx
            .read
            .projects(budget(after)?)
            .map_err(|e| store_error(&e))?;
        result.extend(
            page.items()
                .iter()
                .map(|record| project_name(&record.current.body))
                .collect::<Result<Vec<_>>>()?,
        );
        if let Some(next) = page.next() {
            after = Some(next.clone());
            continue;
        }
        if !page.window().complete() {
            return Err(scope::unreadable(
                "project control inventory",
                "finite window is incomplete",
            ));
        }
        return Ok(result);
    }
    Err(scope::unreadable(
        "project control inventory",
        "more than 6400 projects; select one project explicitly",
    ))
}
fn project_name(body: &EventBody<se_store::StoredText>) -> Result<Named<ProjectId>> {
    match body {
        EventBody::ProjectRegistered { project, name, .. }
        | EventBody::ProjectUpdated { project, name, .. } => Ok(Named {
            id: project.clone(),
            name: name.clone(),
        }),
        _ => Err(scope::unreadable(
            "project control inventory",
            "non-active project metadata",
        )),
    }
}
pub fn agents<R: Snapshot>(
    project: Named<ProjectId>,
    cx: &mut Cx<'_, R>,
) -> Result<Vec<ControlAgent>> {
    let mut targets = Vec::new();
    let mut after = None;
    for _ in 0..64 {
        let page = cx
            .read
            .principals(budget(after)?)
            .map_err(|e| store_error(&e))?;
        for principal in page.items() {
            let agent = match &principal.current.body {
                EventBody::PrincipalRegistered {
                    principal: Actor::Agent(agent),
                    ..
                }
                | EventBody::PrincipalRenamed {
                    principal: Actor::Agent(agent),
                    ..
                } => agent.clone(),
                _ => continue,
            };
            targets.push(control(project.clone(), agent, cx)?);
        }
        if let Some(next) = page.next() {
            after = Some(next.clone());
            continue;
        }
        if !page.window().complete() {
            return Err(scope::unreadable(
                "agent control inventory",
                "finite window is incomplete",
            ));
        }
        return Ok(targets);
    }
    Err(scope::unreadable(
        "agent control inventory",
        "more than 6400 agents; select an exact target",
    ))
}
pub fn control<R: Snapshot>(
    project: Named<ProjectId>,
    agent: AgentId,
    cx: &mut Cx<'_, R>,
) -> Result<ControlAgent> {
    let control = scope::require_present(
        cx.read
            .control_target(agent.clone())
            .map_err(|e| store_error(&e))?,
        "stop target",
        "Choose your own agent or a direct child you are currently allowed to control.",
    )?;
    let name = match &control.principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name.clone()
        }
        _ => return Err(scope::unreadable("stop target", "wrong principal metadata")),
    };
    let profile = scope::require_present(
        control.profile.clone(),
        "stop profile",
        "Restore the target's saved provider profile.",
    )?;
    let provider = match profile.current.body {
        EventBody::ProfileSaved { profile, .. } => match profile.provider {
            se_store::Provider::Claude => se_types::Provider::Claude,
            se_store::Provider::Codex => se_types::Provider::Codex,
            se_store::Provider::SeCode => {
                return Err(SeError::invalid(
                    "managed stop target",
                    "a standalone agent",
                ));
            }
        },
        _ => return Err(scope::unreadable("stop profile", "wrong profile metadata")),
    };
    Ok(ControlAgent {
        target: StopTarget {
            project,
            agent: Named { id: agent, name },
            session_id: None,
            launch_id: None,
            provider,
            process: None,
        },
        control,
    })
}
pub fn plan<R: Snapshot>(input: AgentStop, cx: &mut Cx<'_, R>) -> Result<StopPlan> {
    input.validate()?;
    if (input.all || input.release) && !matches!(cx.admission.actor, Actor::Human(_)) {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "stop --all / --release".into(),
            },
        )));
    }
    let projects = projects(cx)?;
    let targets = if !input.all {
        let project = projects
            .first()
            .filter(|_| projects.len() == 1)
            .ok_or_else(|| SeError::invalid("stop project", "one selected project"))?
            .clone();
        let agent = process_plan::target(
            input.target_agent_id.as_ref(),
            input.owner_agent.as_deref(),
            cx,
        )?;
        vec![control(project, agent, cx)?]
    } else if matches!(cx.admission.scope, Scope::Project(_)) {
        agents(projects[0].clone(), cx)?
    } else {
        Vec::new()
    };
    Ok(StopPlan {
        input,
        projects,
        targets,
    })
}
