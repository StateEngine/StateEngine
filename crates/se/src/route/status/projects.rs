//! Owner-scoped project summaries. Counts come from each project's own finite
//! snapshot; a past session is not a current native liveness observation.
use super::*;
pub(super) fn page<R: ReadStore>(
    reader: &R,
    admission: &Admission,
) -> Result<se_types::Page<ProjectSummary>> {
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
                match snap.sessions(super::super::select::budget(None)?) {
                    Ok(sessions) => {
                        agents_running = (sessions.items().is_empty()
                            && sessions.window().complete())
                        .then_some(0)
                    }
                    Err(error) => errors.push(store_error(&error).body),
                }
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
                if let Err(error) = snap.close() {
                    errors.push(store_error(&error).body);
                    agents_running = None;
                    owner_unread = None;
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

#[cfg(test)]
#[path = "projects/tests.rs"]
mod tests;
