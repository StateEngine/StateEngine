//! Pure status rows are collected on the admission/planning snapshot.
use crate::phase_trace::HostPhaseSpan;

use se_core::{commit::Cx, ops::*, scope, store_error::store_error};
use se_store::{Actor, EventBody, MessageQuery, Snapshot};
use se_types::{Read, Result};

pub(crate) fn prepare<S: Snapshot>(
    input: ProjectStatus,
    home: &std::path::Path,
    cx: &mut Cx<'_, S>,
) -> Result<AnyOutput> {
    let _phase = HostPhaseSpan::new("host_status_prepare");
    if input.all {
        return Err(error("host status", "use the owner CLI for status --all"));
    }
    let generated = receipt::timestamp(super::start::now_unix_micros()?)?;
    let mut status = se_core::ops::status::missing(
        home.display().to_string(),
        generated,
        "no project selected".into(),
    );
    status.setup.state = SetupState::Configured;
    status.setup.reason = None;
    project(&mut status, cx)?;
    Ok(status.into())
}

fn project<S: Snapshot>(output: &mut StatusOutput, cx: &mut Cx<'_, S>) -> Result<()> {
    let se_store::Scope::Project(project) = &cx.admission.scope else {
        return Ok(());
    };
    let record = scope::require_present(
        cx.read
            .project(project.clone())
            .map_err(|e| store_error(&e))?,
        "selected project",
        "Select an existing project in this data home.",
    )?;
    output.scope = "project".into();
    if let Some(removal) = project_remove::removed_view(&record)? {
        output.project = Read::Absent {
            checked: format!("project {} was removed", removal.project.name),
        };
        output.removal = Some(removal);
        output.capture.state = "off".into();
        output.atlas.state = "absent".into();
        return Ok(());
    }
    let (name, roots) = match &record.current.body {
        EventBody::ProjectRegistered { name, roots, .. }
        | EventBody::ProjectUpdated { name, roots, .. } => (name, roots.as_slice()),
        EventBody::ProjectMoved { name, to, .. } => (name, std::slice::from_ref(to)),
        _ => {
            return Err(error(
                "selected project",
                "active project metadata is unavailable",
            ));
        }
    };
    output.project = Read::Present {
        value: ProjectView {
            id: project.clone(),
            name: name.clone(),
            root: roots
                .first()
                .map(|root| root.path.to_local().map(|path| path.display().to_string()))
                .transpose()?
                .unwrap_or_default(),
            registered_at: receipt::timestamp(
                record
                    .original
                    .as_deref()
                    .unwrap_or(&record.current)
                    .recorded_at_us,
            )?,
            git: None,
        },
    };
    let unread = cx
        .read
        .message_count(MessageQuery {
            sender: None,
            recipient: Some(cx.admission.actor.clone()),
            kind: None,
            unread_only: true,
            full_body: false,
        })
        .map_err(|e| store_error(&e))?;
    match &cx.admission.actor {
        Actor::Remote(_) => {
            return Err(se_types::SeError::invalid(
                "local status",
                "local human or agent authority",
            ));
        }
        Actor::Human(_) => output.inbox.owner_unread = Some(unread),
        Actor::Agent(agent) => {
            output.inbox.self_unread = Some(unread);
            if let Some(session) = &cx.admission.session {
                output.principal = Some(PrincipalView {
                    project: Named {
                        id: project.clone(),
                        name: name.clone(),
                    },
                    agent: receipt::named_agent(cx.read, agent)?,
                    session_id: session.clone(),
                });
            }
        }
    }
    output.agents = Some(
        se_core::ops::listing::agents(
            AgentList {
                limit: 100,
                cursor: None,
            },
            cx,
        )?
        .page,
    );
    output.next = NextStep {
        text: "Read this agent's saved state.".into(),
        command: "se agent show main".into(),
        argv: vec!["se".into(), "agent".into(), "show".into(), "main".into()],
    };
    Ok(())
}

fn error(subject: &str, cause: impl std::fmt::Debug) -> se_types::SeError {
    scope::unreadable(subject, &format!("{cause:?}"))
}
