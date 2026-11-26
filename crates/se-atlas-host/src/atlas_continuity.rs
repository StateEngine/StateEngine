//! Optional code context borrows the same admitted snapshot as core continuity.
//! Consumers without an acknowledgement discard the offer and may see it again.
use crate::atlas_runtime::{read_port::AtlasOwnerPort, record_fence::RecordFeedTicket};
use se_store::{Actor, Admission, Scope, SqliteSnapshot};
use se_types::{Read, Result, SeError, code::*};
use std::time::{Duration, Instant};

pub(crate) fn source(
    owner: &AtlasOwnerPort,
    ticket: Option<RecordFeedTicket>,
    read: &mut SqliteSnapshot,
    admission: &Admission,
) -> Result<ResumeCode> {
    let started = Instant::now();
    let (Scope::Project(project), Actor::Agent(viewer)) = (&admission.scope, &admission.actor)
    else {
        return Err(SeError::invalid(
            "Atlas continuity viewer",
            "the verified project agent and active session",
        ));
    };
    crate::atlas_queries::request_project(owner, read, project, None)?;
    let index = owner.summary(project, None)?;
    if &index.project != project {
        return Err(SeError::invalid(
            "Atlas continuity project",
            "the admitted registered project",
        ));
    }
    let state = short_circuit_state(&index.state);
    if let Some(state) = state {
        return Ok(ResumeCode {
            index,
            state,
            items: Vec::new(),
            omitted: None,
            unattributed_omitted: None,
            complete: false,
            omitted_since: None,
            advance: None,
            diagnostic: None,
        });
    }
    let epoch = index
        .epoch
        .as_ref()
        .ok_or_else(|| SeError::invalid("Atlas continuity epoch", "a published scoped epoch"))?;
    let head = read
        .atlas_resume_cursor(viewer, &index.root, epoch)
        .map_err(|e| se_core::store_error::store_error(&e))?;
    let (saved_cursor, cursor_revision) = match head {
        Read::Present { value } => (value.cursor, value.revision),
        Read::Unknown { .. } | Read::Absent { .. } => (None, 0),
        Read::Unreadable { source, reason, .. } => {
            return Err(se_core::scope::unreadable(&source, &reason));
        }
    };
    let engine = owner.engine(project, Some(&index.root))?;
    let mut output = engine.resume(&ResumeRequest {
        viewer: viewer.clone(),
        saved_cursor,
        cursor_revision,
        recently_edited_symbols: Vec::new(),
    })?;
    if output.index.epoch.as_ref() != Some(epoch) {
        return Err(SeError::invalid(
            "Atlas continuity epoch",
            "one unchanged store epoch",
        ));
    }
    let scope = crate::atlas_runtime::record_fence::RecordFeedScope {
        project: project.clone(),
        root: index.root.clone(),
        epoch: epoch.clone(),
    };
    if !owner.records.is_current(&scope, ticket)? {
        output.index.note(CoverageReason::RecordFeedLag);
    }
    fit(&mut output, viewer)?;
    if started.elapsed() > Duration::from_millis(20) {
        return Err(se_types::SeError::new(
            se_types::Detail::AtlasResourceBudget(se_types::details::AtlasResourceBudget {
                resource: "Atlas resume wall deadline".into(),
                requested: 1,
                available: 0,
            }),
        ));
    }
    Ok(output)
}
/// Drop items until the rendered context fits; past that, no offer at all.
/// An offer that loses items carries a retrieval cursor for what it left
/// out, so acknowledging it never skips them.
fn fit(output: &mut ResumeCode, viewer: &se_types::AgentId) -> Result<()> {
    loop {
        if se_atlas::render::resume(output).is_ok() {
            return Ok(());
        }
        if output.items.pop().is_none() {
            output.state = ResumeCodeState::BudgetExceeded;
            output.omitted_since = None;
            output.advance = None;
            output.diagnostic = Some(
                SeError::new(se_types::Detail::AtlasResourceBudget(
                    se_types::details::AtlasResourceBudget {
                        resource: "Atlas resume context including retrieval".into(),
                        requested: 601,
                        available: 600,
                    },
                ))
                .body,
            );
            return Ok(());
        }
        output.omitted = output.omitted.map(|n| n + 1);
        output.complete = false;
        if output.omitted_since.is_none() {
            output.omitted_since = se_atlas_service::resume_retrieval(output, viewer)?;
        }
    }
}
fn short_circuit_state(state: &IndexState) -> Option<ResumeCodeState> {
    match state {
        IndexState::Disabled | IndexState::NotBuilt => Some(ResumeCodeState::Disabled),
        IndexState::Dormant | IndexState::Absent => Some(ResumeCodeState::NeverIndexed),
        IndexState::Opening
        | IndexState::ColdIndexing { .. }
        | IndexState::Draining
        | IndexState::Closed => Some(ResumeCodeState::Updating),
        IndexState::Unreadable { .. } | IndexState::Suspended { .. } => {
            Some(ResumeCodeState::Unreadable)
        }
        _ => None,
    }
}
/// The map may take this long on top of the code context; its query is
/// interrupted there, and the orientation says so rather than slowing resume.
const MAP_DEADLINE: Duration = Duration::from_millis(15);
/// Open assignments read to find this agent's; more are reported as cut short.
const ASSIGNMENT_PAGE: u16 = 50;

/// The agent's orientation: the index's map when it can be read in time, and
/// the open assignments the store tracks for the agent. Never fails: a part
/// that cannot be read says so in place.
fn orientation(
    owner: &AtlasOwnerPort,
    read: &mut SqliteSnapshot,
    admission: &Admission,
) -> Orientation {
    let (Scope::Project(project), Actor::Agent(viewer)) = (&admission.scope, &admission.actor)
    else {
        return Orientation {
            map: None,
            map_note: Some("no bound project agent".into()),
            assignments: Vec::new(),
            more_assignments: false,
        };
    };
    let deadline = Instant::now() + MAP_DEADLINE;
    let (map, map_note) = match owner.summary(project, None) {
        Ok(summary) if crate::atlas_queries::readable(&summary) => {
            match owner
                .engine(project, Some(&summary.root))
                .and_then(|engine| engine.repo_map(deadline))
            {
                Ok(Some(map)) => (Some(map), None),
                Ok(None) => (None, Some("over its 15 ms time budget".into())),
                Err(error) => (None, Some(format!("unreadable: {}", error.body.message()))),
            }
        }
        Ok(summary) => (
            None,
            Some(match summary.state {
                IndexState::Disabled | IndexState::NotBuilt => "Atlas is disabled".into(),
                _ => "the Atlas index is not ready; se status shows its progress".into(),
            }),
        ),
        Err(error) => (None, Some(format!("unreadable: {}", error.body.message()))),
    };
    let (assignments, more_assignments) = assignments(read, admission, viewer);
    Orientation {
        map,
        map_note,
        assignments,
        more_assignments,
    }
}
/// This agent's open assignments from the first page of the project's.
fn assignments(
    read: &mut SqliteSnapshot,
    admission: &Admission,
    viewer: &se_types::AgentId,
) -> (Vec<AssignmentLink>, bool) {
    let mut cx = se_core::commit::Cx { read, admission };
    let input = se_core::ops::assignment::AssignmentList {
        limit: ASSIGNMENT_PAGE,
        cursor: None,
    };
    let Ok(page) = se_core::ops::assignment::list(input, &mut cx) else {
        return (Vec::new(), true);
    };
    let more = !page.page.window().complete() || page.page.next().is_some();
    let links = page
        .page
        .into_items()
        .into_iter()
        .filter(|row| &row.assignee == viewer)
        .map(|row| AssignmentLink {
            id: row.id,
            state: row.state,
            preview: match row.preview {
                Some(Read::Present { value }) => Some(value),
                _ => None,
            },
        })
        .collect();
    (links, more)
}
fn failed(error: &SeError) -> ResumeCodeState {
    if matches!(
        error.body.detail(),
        se_types::Detail::AtlasResourceBudget(_)
    ) {
        ResumeCodeState::BudgetExceeded
    } else {
        ResumeCodeState::Unreadable
    }
}
pub fn attach(
    owner: &AtlasOwnerPort,
    ticket: Option<RecordFeedTicket>,
    read: &mut SqliteSnapshot,
    admission: &Admission,
    output: &mut se_core::ops::AnyOutput,
    context_bytes: Option<u32>,
) -> Result<()> {
    if !matches!(
        (&admission.actor, &admission.session),
        (Actor::Agent(_), Some(_))
    ) {
        return Ok(());
    }
    if !matches!(
        output,
        se_core::ops::AnyOutput::Resume(_) | se_core::ops::AnyOutput::SessionContext(_)
    ) {
        return Ok(());
    }
    let source = source(owner, ticket, read, admission);
    match output {
        se_core::ops::AnyOutput::Resume(value) => {
            match source {
                Ok(source) => {
                    drop(se_core::atlas_resume::attach_resume(
                        &mut value.value,
                        source,
                        600,
                    )?);
                }
                Err(error) => se_core::atlas_resume::attach_resume_status(
                    &mut value.value,
                    failed(&error),
                    600,
                )?,
            }
            se_core::orientation::attach_resume(
                &mut value.value,
                orientation(owner, read, admission),
            )?;
        }
        se_core::ops::AnyOutput::SessionContext(value) => {
            let bytes = context_bytes.ok_or_else(|| {
                SeError::invalid(
                    "Atlas context budget",
                    "the caller's original context allocation",
                )
            })?;
            match source {
                Ok(source) => {
                    drop(se_core::atlas_resume::attach_context(
                        &mut value.value,
                        source,
                        bytes,
                        600,
                    )?);
                }
                Err(error) => se_core::atlas_resume::attach_context_status(
                    &mut value.value,
                    failed(&error),
                    bytes,
                    600,
                )?,
            }
            se_core::orientation::attach_context(
                &mut value.value,
                orientation(owner, read, admission),
                bytes,
            )?;
        }
        _ => (),
    }
    Ok(())
}

pub fn attach_model(
    owner: &AtlasOwnerPort,
    ticket: Option<RecordFeedTicket>,
    read: &mut SqliteSnapshot,
    admission: &Admission,
    text: &mut String,
    maximum: u32,
) -> Result<()> {
    let (Scope::Project(project), Actor::Agent(viewer)) = (&admission.scope, &admission.actor)
    else {
        return Err(SeError::invalid(
            "native code context",
            "one bound project and agent",
        ));
    };
    let source = source(owner, ticket, read, admission).map_err(|error| failed(&error));
    // The current linked consumer has no acknowledgement for this section.
    // Preserve its cursor instead of equating returning a future with delivery.
    drop(se_core::atlas_resume::attach_model_input(
        text, source, project, viewer, maximum, 600,
    )?);
    se_core::orientation::attach_model_input(text, orientation(owner, read, admission), maximum)
}
