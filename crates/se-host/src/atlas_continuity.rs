//! Optional code context borrows the same admitted snapshot as core continuity.
//! Consumers without an acknowledgement discard the offer and may see it again.
use crate::{
    atlas_records::AtlasRecordReader,
    atlas_runtime::{read_port::AtlasOwnerPort, record_fence::RecordFeedTicket},
};
use se_atlas::query::{QueryReader, ReaderContext};
use se_store::{Actor, Admission, Scope, SqliteSnapshot};
use se_types::{Read, Result, SeError, code::*};
use std::time::{Duration, Instant};

pub(crate) fn source(
    owner: &AtlasOwnerPort,
    ticket: Option<RecordFeedTicket>,
    read: &mut SqliteSnapshot,
    admission: &Admission,
    now: i64,
) -> Result<ResumeCode> {
    let started = Instant::now();
    let (Scope::Project(project), Actor::Agent(viewer)) = (&admission.scope, &admission.actor)
    else {
        return Err(SeError::invalid(
            "Atlas continuity viewer",
            "the verified project agent and active session",
        ));
    };
    let index = owner.summary(project, None)?;
    if &index.project != project {
        return Err(SeError::invalid(
            "Atlas continuity project",
            "the admitted registered project",
        ));
    }
    let state = match &index.state {
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
    };
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
    let mut output = None;
    owner.with_observed_reader(
        project,
        Some(&index.root),
        ticket,
        &mut |cache, source, observed| {
            if output.is_some() || cache.identity().epoch != *epoch {
                return Err(SeError::invalid(
                    "Atlas continuity epoch",
                    "one unchanged borrowed epoch",
                ));
            }
            let records = AtlasRecordReader::new(read, admission);
            let query = QueryReader::new(
                cache,
                ReaderContext {
                    memory: observed.summary.memory,
                    viewer: AtlasPrincipal::Agent(viewer.clone()),
                    records: &records,
                    source: Some(source),
                    hostless: false,
                    epoch_retired: observed.epoch_retired,
                    now_unix_ms: Some(now),
                    record_feed_current: observed.record_feed_current,
                },
            )
            .with_source_state(observed.summary.state);
            output = Some(query.resume_code(&ResumeRequest {
                viewer: viewer.clone(),
                saved_cursor: saved_cursor.clone(),
                cursor_revision,
                recently_edited_symbols: Vec::new(),
            })?);
            Ok(())
        },
    )?;
    if started.elapsed() > Duration::from_millis(20) {
        return Err(se_types::SeError::new(
            se_types::Detail::AtlasResourceBudget(se_types::details::AtlasResourceBudget {
                resource: "Atlas resume wall deadline".into(),
                requested: 1,
                available: 0,
            }),
        ));
    }
    output
        .ok_or_else(|| SeError::invalid("Atlas continuity read", "one completed borrowed callback"))
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
pub(crate) fn attach(
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
    let source = source(
        owner,
        ticket,
        read,
        admission,
        crate::runtime::start::now_unix_micros()? / 1000,
    );
    match output {
        se_core::ops::AnyOutput::Resume(value) => match source {
            Ok(source) => {
                drop(se_core::atlas_resume::attach_resume(
                    &mut value.value,
                    source,
                    600,
                )?);
            }
            Err(error) => {
                se_core::atlas_resume::attach_resume_status(&mut value.value, failed(&error), 600)?
            }
        },
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
        }
        _ => (),
    }
    Ok(())
}

#[cfg(feature = "secode")]
pub(crate) fn attach_model(
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
    let source = source(
        owner,
        ticket,
        read,
        admission,
        crate::runtime::start::now_unix_micros()? / 1000,
    )
    .map_err(|error| failed(&error));
    // The current linked consumer has no acknowledgement for this section.
    // Preserve its cursor instead of equating returning a future with delivery.
    drop(se_core::atlas_resume::attach_model_input(
        text, source, project, viewer, maximum, 600,
    )?);
    Ok(())
}
