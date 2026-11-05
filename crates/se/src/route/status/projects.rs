//! Owner-scoped project summaries. Counts come from each project's own finite
//! snapshot; native observations run only after that snapshot closes.
use super::*;
pub(super) fn page<R: ReadStore>(
    reader: &R,
    admission: &Admission,
) -> Result<se_types::Page<ProjectSummary>> {
    let deadline = super::super::session_observation::deadline()?;
    let mut snap = reader
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let result = snap
        .projects(super::super::select::budget(None)?)
        .map_err(|e| store_error(&e));
    let closed = snap.close().map_err(|e| store_error(&e));
    let page = match result {
        Ok(page) => {
            closed?;
            page
        }
        Err(error) => {
            return Err(match closed {
                Ok(()) => error,
                Err(close) => error.with_cause(close),
            });
        }
    };
    let mut fields =
        page.window().fields().cloned().ok_or_else(|| {
            scope::unreadable("registered projects", "window accounting is absent")
        })?;
    let next = page.next().cloned();
    let mut rows = Vec::new();
    for record in page.into_items() {
        let (id, name, roots) = match record.current.body {
            EventBody::ProjectRegistered {
                project,
                name,
                roots,
                ..
            }
            | EventBody::ProjectUpdated {
                project,
                name,
                roots,
                ..
            } => (project, name, roots),
            EventBody::ProjectMoved {
                project, name, to, ..
            } => (project, name, vec![to.clone()]),
            _ => {
                return Err(scope::unreadable(
                    "registered project",
                    "active metadata has an unexpected event kind",
                ));
            }
        };
        let mut errors = Vec::new();
        let root = match roots
            .first()
            .ok_or_else(|| scope::unreadable("registered project", "repository root is absent"))
            .and_then(|root| root.path.to_local())
        {
            Ok(path) => Some(path.display().to_string()),
            Err(error) => {
                errors.push(error.body);
                None
            }
        };
        let mut project_admission = admission.clone();
        project_admission.scope = Scope::Project(id.clone());
        let mut agents_running = None;
        let mut owner_unread = None;
        match reader.snapshot(read_scope(&project_admission)) {
            Err(error) => errors.push(store_error(&error).body),
            Ok(mut snap) => {
                let observed = super::super::select::budget(None)
                    .and_then(|budget| prepare_running(&mut snap, &project_admission, budget));
                match snap.message_count(MessageQuery {
                    sender: None,
                    recipient: Some(admission.actor.clone()),
                    kind: None,
                    unread_only: true,
                    full_body: false,
                }) {
                    Ok(count) => owner_unread = Some(count),
                    Err(error) => errors.push(store_error(&error).body),
                }
                match snap.close() {
                    Err(error) => {
                        if let Err(read_error) = observed {
                            errors.push(read_error.body);
                        }
                        errors.push(store_error(&error).body);
                        owner_unread = None;
                    }
                    Ok(()) => match observed.and_then(|rows| count_running(rows, deadline)) {
                        Ok(count) => agents_running = Some(count),
                        Err(error) => errors.push(error.body),
                    },
                }
            }
        }
        rows.push(ProjectSummary {
            id,
            name,
            root,
            agents_running,
            owner_unread,
            errors,
        });
    }
    fields.returned = rows.len() as u64;
    fields.bytes = serde_json::to_vec(&rows)
        .map_err(|e| scope::unreadable("project summaries", &e.to_string()))?
        .len() as u64;
    if fields.bytes > u64::from(fields.max_bytes.get()) {
        return Err(scope::unreadable(
            "project summaries",
            "expanded rows exceed the response byte budget",
        ));
    }
    se_types::Page::new(rows, se_types::Window::new(fields)?, next)
}

/// Copy the same saved-agent rows and native plans as project status. A finite
/// partial page cannot supply an exact project-wide count.
fn prepare_running<S: Snapshot>(
    snap: &mut S,
    admission: &Admission,
    budget: se_store::ReadBudget,
) -> Result<Vec<(AgentRow, se_host::AgentObservationPlan)>> {
    let page = agent_status::page(
        budget,
        &mut se_core::commit::Cx {
            read: snap,
            admission,
        },
    )?;
    if !page.window().complete() {
        return Err(scope::unreadable(
            "project running-agent count",
            "The saved-agent page is incomplete; inspect this project's paginated agent list before trusting a total.",
        ));
    }
    let project = scope::project(admission)?;
    page.into_items()
        .into_iter()
        .map(|row| {
            let plan = se_host::prepare_agent_observation(&project, &row, snap)?;
            Ok((row, plan))
        })
        .collect()
}
fn count_running(
    rows: Vec<(AgentRow, se_host::AgentObservationPlan)>,
    deadline: std::time::Instant,
) -> Result<u64> {
    let mut running = 0;
    for (mut row, plan) in rows {
        se_host::observe_agent(plan, deadline)?.apply(&mut row)?;
        match &row.session.liveness {
            Read::Unknown { what } => {
                return Err(scope::unreadable(
                    &format!("running-agent count for agent {}", row.id),
                    what,
                ));
            }
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(
                    &format!("running-agent count for agent {}", row.id),
                    &format!("{source}: {reason}"),
                ));
            }
            _ => (),
        }
        if row.session.state == "unknown" {
            return Err(scope::unreadable(
                &format!("running-agent count for agent {}", row.id),
                "The same native observation used by project status could not determine this session's state.",
            ));
        }
        running += u64::from(row.session.state == "running");
    }
    Ok(running)
}

#[cfg(test)]
#[path = "projects/tests.rs"]
mod tests;
