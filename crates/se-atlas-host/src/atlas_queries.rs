//! Admitted Atlas reads on the owner's v5 engine. Queries register the
//! project's worktrees and signal interest; they never start a build
//! themselves, and records reach an answer only through core's check.
#[cfg(feature = "listener")]
use crate::atlas_records::AtlasRecordReader;
use se_atlas::errors::AtlasResult;
use se_store::Snapshot;
#[cfg(feature = "listener")]
use se_store::{Actor, Admission, Scope};
#[cfg(feature = "listener")]
use se_types::{ProjectId, Read};
use se_types::{SeError, code::*};

/// One presentation path for CLI and MCP. JSON remains the typed wire family.
pub use se_mcp::compact;

/// The admitted viewer; remote grants never read Atlas.
#[cfg(feature = "listener")]
pub(crate) fn principal(admission: &Admission) -> AtlasResult<AtlasPrincipal> {
    match &admission.actor {
        Actor::Agent(agent) => Ok(AtlasPrincipal::Agent(agent.clone())),
        Actor::Human(human) => Ok(AtlasPrincipal::Human(human.clone())),
        Actor::Guest => Ok(AtlasPrincipal::Guest),
        Actor::Remote(_) => Err(SeError::invalid(
            "Atlas query principal",
            "an admitted local Owner or agent; remote grants cover list, watch and send only",
        )),
    }
}

/// Core's record check for one admitted viewer, lent to the engine.
#[cfg(feature = "listener")]
pub(crate) struct CheckedRecords<'a, R: Snapshot> {
    reader: AtlasRecordReader<'a, R>,
    project: ProjectId,
    viewer: AtlasPrincipal,
}

#[cfg(feature = "listener")]
impl<'a, R: Snapshot> CheckedRecords<'a, R> {
    pub(crate) fn new(
        read: &'a mut R,
        admission: &'a Admission,
        project: ProjectId,
    ) -> AtlasResult<Self> {
        Ok(Self {
            viewer: principal(admission)?,
            reader: AtlasRecordReader::new(read, admission),
            project,
        })
    }
}

#[cfg(feature = "listener")]
impl<R: Snapshot> se_atlas_service::RecordCheck for CheckedRecords<'_, R> {
    fn hit(
        &self,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> se_types::Result<Read<RecordHit>> {
        self.reader
            .read(&self.project, &self.viewer, pointer, query)
    }
}

/// States whose store an engine can read, even while it is still building.
pub(crate) fn readable(summary: &IndexSummary) -> bool {
    summary.epoch.is_some()
        && matches!(
            summary.state,
            IndexState::Current
                | IndexState::Updating { .. }
                | IndexState::VerificationNeeded { .. }
                | IndexState::ColdIndexing { .. }
                | IndexState::Partial { .. }
        )
}

/// Execute inside the existing admitted core read phase. No read lease or
/// borrowed handle survives the call.
#[cfg(feature = "listener")]
pub fn owner_read<R: Snapshot>(
    owner: &crate::atlas_runtime::read_port::AtlasOwnerPort,
    ticket: Option<crate::atlas_runtime::record_fence::RecordFeedTicket>,
    request: &se_core::ops::AtlasRead,
    read: &mut R,
    admission: &Admission,
    _now_unix_ms: i64,
) -> AtlasResult<se_core::ops::AnyOutput> {
    let Scope::Project(project) = &admission.scope else {
        return Err(SeError::invalid(
            "Atlas query scope",
            "one admitted registered project",
        ));
    };
    let root = request.options().root.as_ref();
    request_project(owner, read, project, root)?;
    let summary = owner.summary(project, root)?;
    if &summary.project != project || root.is_some_and(|root| root != &summary.root) {
        return Err(SeError::invalid(
            "Atlas summary scope",
            "the admitted project's selected registered root",
        ));
    }
    if !readable(&summary) {
        return Ok(unavailable(request, summary));
    }
    let engine = owner.engine(project, root)?;
    let feed_current = match &summary.epoch {
        Some(epoch) => owner.records.is_current(
            &crate::atlas_runtime::record_fence::RecordFeedScope {
                project: project.clone(),
                root: summary.root.clone(),
                epoch: epoch.clone(),
            },
            ticket,
        )?,
        None => false,
    };
    let viewer = principal(admission)?;
    let records = CheckedRecords::new(read, admission, project.clone())?;
    let mut output = execute_v5(&engine, request, &records, &viewer)?;
    if !feed_current {
        note(&mut output, CoverageReason::RecordFeedLag);
    }
    Ok(output)
}

#[cfg(feature = "listener")]
fn execute_v5(
    engine: &se_atlas_service::Root,
    request: &se_core::ops::AtlasRead,
    records: &dyn se_atlas_service::RecordCheck,
    viewer: &AtlasPrincipal,
) -> AtlasResult<se_core::ops::AnyOutput> {
    use se_core::ops::{
        AtlasChangesOutput, AtlasFindOutput, AtlasImpactOutput, AtlasOutlineOutput, AtlasRead,
        AtlasRefsOutput,
    };
    Ok(match request {
        AtlasRead::Find(input) => AtlasFindOutput {
            answer: engine.find(&input.query()?, records)?,
        }
        .into(),
        AtlasRead::Refs(input) => AtlasRefsOutput {
            answer: engine.refs(&input.query()?)?,
        }
        .into(),
        AtlasRead::Impact(input) => AtlasImpactOutput {
            answer: engine.impact(&input.query()?, records)?,
        }
        .into(),
        AtlasRead::Changes(input) => AtlasChangesOutput {
            answer: engine.changes(&input.query()?, viewer)?,
        }
        .into(),
        AtlasRead::Outline(input) => AtlasOutlineOutput {
            answer: engine.outline(&input.query()?, records)?,
        }
        .into(),
    })
}

/// Record a coverage gap that leaves the code index's own state alone.
#[cfg(feature = "listener")]
fn note(output: &mut se_core::ops::AnyOutput, reason: CoverageReason) {
    use se_core::ops::AnyOutput;
    match output {
        AnyOutput::AtlasFind(v) => v.value.answer.index.note(reason),
        AnyOutput::AtlasRefs(v) => v.value.answer.index.note(reason),
        AnyOutput::AtlasImpact(v) => v.value.answer.index.note(reason),
        AnyOutput::AtlasChanges(v) => v.value.answer.index.note(reason),
        AnyOutput::AtlasOutline(v) => v.value.answer.index.note(reason),
        _ => (),
    }
}

/// Read, hook and continuity callers use the same current authoritative
/// registration as explicit queries. Status never calls this.
pub(crate) fn request_project<R: Snapshot>(
    owner: &crate::atlas_runtime::read_port::AtlasOwnerPort,
    read: &mut R,
    project: &se_types::ProjectId,
    root: Option<&RootId>,
) -> AtlasResult<()> {
    let registered = se_core::scope::require_present(
        read.project(project.clone())
            .map_err(|e| se_core::store_error::store_error(&e))?,
        "Atlas project",
        "Select an existing registered project before querying Atlas.",
    )?;
    let roots = match registered.current.body {
        se_store::EventBody::ProjectRegistered { roots, .. }
        | se_store::EventBody::ProjectUpdated { roots, .. } => roots,
        se_store::EventBody::ProjectMoved { to, .. } => vec![to],
        _ => {
            return Err(SeError::invalid(
                "Atlas project",
                "an active registered project",
            ));
        }
    };
    owner.observe_project(project, &roots)?;
    owner.request_interest(project, root)?;
    Ok(())
}

#[cfg(feature = "listener")]
fn unavailable(request: &se_core::ops::AtlasRead, index: IndexSummary) -> se_core::ops::AnyOutput {
    use se_core::ops::*;
    fn answer<T>(index: IndexSummary) -> Answer<se_types::Read<T>> {
        let data = match &index.state {
            IndexState::Unreadable { error } => se_types::Read::Unreadable {
                source: "registered Atlas index".into(),
                reason: error.message(),
                error: Some(Box::new(error.clone())),
            },
            IndexState::Suspended { reason } => se_types::Read::Unknown {
                what: reason.message(),
            },
            state => se_types::Read::Unknown {
                what: match state {
                    IndexState::Disabled => {
                        "Atlas is explicitly disabled; edit [atlas] enabled = true in the selected config.toml, then run se down and se up with the same --home"
                    }
                    IndexState::NotBuilt => "Atlas is not compiled into this build",
                    IndexState::Dormant | IndexState::Absent => {
                        "The registered Atlas index has no published snapshot"
                    }
                    IndexState::Draining | IndexState::Closed => {
                        "The registered Atlas index has closed reader admission"
                    }
                    _ => se_atlas_service::STARTING,
                }
                .into(),
            },
        };
        Answer {
            index,
            snapshot_advanced: false,
            epoch_retired: false,
            data,
        }
    }
    match request {
        AtlasRead::Find(_) => AtlasFindOutput {
            answer: answer(index),
        }
        .into(),
        AtlasRead::Refs(_) => AtlasRefsOutput {
            answer: answer(index),
        }
        .into(),
        AtlasRead::Impact(_) => AtlasImpactOutput {
            answer: answer(index),
        }
        .into(),
        AtlasRead::Changes(_) => AtlasChangesOutput {
            answer: answer(index),
        }
        .into(),
        AtlasRead::Outline(_) => AtlasOutlineOutput {
            answer: answer(index),
        }
        .into(),
    }
}
#[cfg(all(test, feature = "listener"))]
mod refusal_tests {
    use super::*;
    /// Bug: PR 186 — the disabled refusal named a setting but no working step.
    #[test]
    fn disabled_refusal_names_the_config_edit_and_the_restart() -> se_types::Result<()> {
        let index = IndexSummary {
            project: "prj_01890000-0000-7000-8000-000000000001".parse()?,
            root: "aroot_01890000-0000-7000-8000-000000000002".parse()?,
            memory: None,
            epoch: None,
            generation: None,
            state: IndexState::Disabled,
            coverage: Coverage::default(),
        };
        let request = se_core::ops::AtlasRead::Find(
            serde_json::from_value(serde_json::json!({"query": "main"}))
                .map_err(|e| SeError::invalid("test request", &e.to_string()))?,
        );
        let se_core::ops::AnyOutput::AtlasFind(out) = unavailable(&request, index) else {
            return Err(SeError::invalid("test output", "a find reply"));
        };
        let se_types::Read::Unknown { what } = out.value.answer.data else {
            return Err(SeError::invalid("test output", "an Unknown refusal"));
        };
        for step in [
            "[atlas]",
            "enabled = true",
            "config.toml",
            "se down",
            "se up",
        ] {
            assert!(what.contains(step), "refusal lacks `{step}`: {what}");
        }
        Ok(())
    }
}
