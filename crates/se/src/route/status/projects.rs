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
        let root = roots
            .first()
            .ok_or_else(|| scope::unreadable("registered project", "repository root is absent"))?
            .path
            .to_local()?
            .display()
            .to_string();
        let mut project_admission = admission.clone();
        project_admission.scope = Scope::Project(id.clone());
        let mut snap = reader
            .snapshot(read_scope(&project_admission))
            .map_err(|e| store_error(&e))?;
        let counts = (|| {
            let sessions = snap
                .sessions(super::super::select::budget(None)?)
                .map_err(|e| store_error(&e))?;
            let agents_running =
                (sessions.items().is_empty() && sessions.window().complete()).then_some(0);
            let owner_unread = snap
                .message_count(MessageQuery {
                    sender: None,
                    recipient: Some(admission.actor.clone()),
                    kind: None,
                    unread_only: true,
                    full_body: false,
                })
                .map_err(|e| store_error(&e))?;
            Ok((agents_running, owner_unread))
        })();
        let closed = snap.close().map_err(|e| store_error(&e));
        let (agents_running, owner_unread) = match counts {
            Ok(value) => {
                closed?;
                value
            }
            Err(error) => {
                return Err(match closed {
                    Ok(()) => error,
                    Err(close) => error.with_cause(close),
                });
            }
        };
        rows.push(ProjectSummary {
            id,
            name,
            root,
            agents_running,
            owner_unread,
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
