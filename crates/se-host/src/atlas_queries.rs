//! Borrow the controller's scoped cache and core's authoritative read together.
//! This adapter cannot activate a root, open another connection or schedule work.
use crate::atlas_records::AtlasRecordReader;
use se_atlas::{
    errors::AtlasResult,
    lifecycle::AtlasController,
    query::{LiveSource, QueryReader, ReaderContext},
};
use se_store::{Actor, Admission, Scope, Snapshot};
use se_types::{SeError, code::*};

/// Host observations fenced against the supplied core snapshot. Unknown record
/// maintenance is false. A hostless reader always labels its snapshot unverified.
pub struct QueryObservations {
    pub hostless: bool,
    pub epoch_retired: bool,
    pub record_feed_current: bool,
    pub now_unix_ms: Option<i64>,
}

/// The runtime invokes this only inside with_reader, after admitted root lookup.
pub fn execute(
    reader: &QueryReader<'_>,
    request: &se_core::ops::AtlasRead,
) -> AtlasResult<se_core::ops::AnyOutput> {
    use se_core::ops::{
        AtlasChangesOutput, AtlasFindOutput, AtlasImpactOutput, AtlasOutlineOutput, AtlasRead,
        AtlasRefsOutput,
    };
    match request {
        AtlasRead::Find(input) => Ok(AtlasFindOutput {
            answer: if input.options.format == AtlasFormat::Compact {
                reader.find_compact(
                    &input.query()?,
                    input.options.byte_budget as usize,
                    input.options.explain,
                )?
            } else {
                reader.find(&input.query()?)?
            },
        }
        .into()),
        AtlasRead::Refs(input) => Ok(AtlasRefsOutput {
            answer: reader.refs(&input.query()?)?,
        }
        .into()),
        AtlasRead::Impact(input) => Ok(AtlasImpactOutput {
            answer: reader.impact(&input.query()?)?,
        }
        .into()),
        AtlasRead::Changes(input) => Ok(AtlasChangesOutput {
            answer: reader.changes(&input.query()?)?,
        }
        .into()),
        AtlasRead::Outline(input) => Ok(AtlasOutlineOutput {
            answer: reader.outline(&input.query()?)?,
        }
        .into()),
    }
}

pub fn with_reader<C, R, T>(
    controller: &C,
    root: RootId,
    read: &mut R,
    admission: &Admission,
    observations: QueryObservations,
    query: impl FnOnce(&QueryReader<'_>) -> AtlasResult<T>,
) -> AtlasResult<T>
where
    C: AtlasController,
    C::Source: LiveSource,
    R: Snapshot,
{
    let Scope::Project(project) = &admission.scope else {
        return Err(SeError::invalid(
            "Atlas query scope",
            "one admitted registered project",
        ));
    };
    let viewer = match &admission.actor {
        Actor::Agent(agent) => AtlasPrincipal::Agent(agent.clone()),
        Actor::Human(human) => AtlasPrincipal::Human(human.clone()),
    };
    let expected_root = root.clone();
    controller.with_reader(root, |cache, source| {
        let registration = &cache.identity().scope.registration;
        if &registration.project != project || registration.root != expected_root {
            return Err(SeError::invalid(
                "Atlas query binding",
                "the admitted project's registered root",
            ));
        }
        let records = AtlasRecordReader::new(read, admission);
        let reader = QueryReader::new(
            cache,
            ReaderContext {
                memory: None,
                viewer,
                records: &records,
                source: Some(source),
                hostless: observations.hostless,
                epoch_retired: observations.epoch_retired,
                record_feed_current: observations.record_feed_current && !observations.hostless,
                now_unix_ms: observations.now_unix_ms,
            },
        );
        query(&reader)
    })
}

/// One presentation path for CLI and MCP. JSON remains the typed wire family.
pub fn compact(
    output: &se_core::ops::AnyOutput,
    max_bytes: usize,
    explain: bool,
) -> AtlasResult<Option<String>> {
    use se_core::ops::AnyOutput;
    let text = match output {
        AnyOutput::AtlasFind(value) => {
            se_atlas::render::search(&value.value.answer, max_bytes, explain)?
        }
        AnyOutput::AtlasRefs(value) => se_atlas::render::refs(&value.value.answer, max_bytes)?,
        AnyOutput::AtlasImpact(value) => se_atlas::render::impact(&value.value.answer, max_bytes)?,
        AnyOutput::AtlasChanges(value) => {
            se_atlas::render::changes(&value.value.answer, max_bytes)?
        }
        AnyOutput::AtlasOutline(value) => {
            se_atlas::render::outline(&value.value.answer, max_bytes)?
        }
        _ => return Ok(None),
    };
    Ok(Some(text))
}

/// Execute inside the existing admitted core read phase, lending the owner's
/// cache/source for the duration. No read lease or borrowed handle survives.
pub(crate) fn owner_read<R: Snapshot>(
    owner: &crate::atlas_runtime::read_port::AtlasOwnerPort,
    ticket: Option<crate::atlas_runtime::record_fence::RecordFeedTicket>,
    request: &se_core::ops::AtlasRead,
    read: &mut R,
    admission: &Admission,
    now_unix_ms: i64,
) -> AtlasResult<se_core::ops::AnyOutput> {
    let Scope::Project(project) = &admission.scope else {
        return Err(SeError::invalid(
            "Atlas query scope",
            "one admitted registered project",
        ));
    };
    let summary = owner.summary(project, request.options().root.as_ref())?;
    if &summary.project != project
        || request
            .options()
            .root
            .as_ref()
            .is_some_and(|root| root != &summary.root)
    {
        return Err(SeError::invalid(
            "Atlas summary scope",
            "the admitted project's selected registered root",
        ));
    }
    if !matches!(
        summary.state,
        IndexState::Current
            | IndexState::Updating { .. }
            | IndexState::VerificationNeeded { .. }
            | IndexState::Opening
            | IndexState::ColdIndexing { .. }
            | IndexState::Suspended { .. }
    ) || summary.epoch.is_none()
    {
        return Ok(unavailable(request, summary));
    }
    with_owner_reader(
        owner,
        ticket,
        request.options().root.as_ref(),
        read,
        admission,
        now_unix_ms,
        |reader, _| execute(reader, request),
    )
}

/// One admitted snapshot and borrowed controller reader for private adapters too.
pub(crate) fn with_owner_reader<R: Snapshot, T>(
    owner: &crate::atlas_runtime::read_port::AtlasOwnerPort,
    ticket: Option<crate::atlas_runtime::record_fence::RecordFeedTicket>,
    root: Option<&RootId>,
    read: &mut R,
    admission: &Admission,
    now_unix_ms: i64,
    query: impl FnOnce(
        &QueryReader<'_>,
        &se_atlas::source::RegisteredSource<crate::atlas_source::NativeAtlasSource>,
    ) -> AtlasResult<T>,
) -> AtlasResult<T> {
    let Scope::Project(project) = &admission.scope else {
        return Err(SeError::invalid(
            "Atlas query scope",
            "one admitted registered project",
        ));
    };
    let viewer = match &admission.actor {
        Actor::Agent(id) => AtlasPrincipal::Agent(id.clone()),
        Actor::Human(id) => AtlasPrincipal::Human(id.clone()),
    };
    let mut query = Some(query);
    let mut output = None;
    owner.with_observed_reader(project, root, ticket, &mut |cache, source, observed| {
        if &cache.identity().scope.registration.project != project
            || root.is_some_and(|root| root != &cache.identity().scope.registration.root)
        {
            return Err(SeError::invalid(
                "Atlas owner callback",
                "the admitted project's selected root",
            ));
        }
        let query = query
            .take()
            .ok_or_else(|| SeError::invalid("Atlas owner callback", "one borrowed callback"))?;
        let records = AtlasRecordReader::new(read, admission);
        let reader = QueryReader::new(
            cache,
            ReaderContext {
                memory: observed.summary.memory,
                viewer: viewer.clone(),
                records: &records,
                source: Some(source),
                hostless: false,
                epoch_retired: observed.epoch_retired,
                now_unix_ms: Some(now_unix_ms),
                record_feed_current: observed.record_feed_current,
            },
        )
        .with_source_state(observed.summary.state);
        output = Some(query(&reader, source)?);
        Ok(())
    })?;
    output.ok_or_else(|| {
        SeError::invalid(
            "Atlas owner read port",
            "one completed scoped query callback",
        )
    })
}

fn unavailable(request: &se_core::ops::AtlasRead, index: IndexSummary) -> se_core::ops::AnyOutput {
    use se_core::ops::*;
    fn answer<T>(index: IndexSummary) -> Answer<se_types::Read<T>> {
        let data = match &index.state {
            IndexState::Unreadable { error } => se_types::Read::Unreadable {
                source: "registered Atlas index".into(),
                reason: error.message(),
                error: Some(Box::new(error.clone())),
            },
            state => se_types::Read::Unknown {
                what: match state {
                    IndexState::Disabled => {
                        "Atlas is explicitly disabled; enable atlas.enabled in configuration"
                    }
                    IndexState::NotBuilt => "Atlas is not compiled into this build",
                    IndexState::Dormant | IndexState::Absent => {
                        "The registered Atlas index has no published snapshot"
                    }
                    IndexState::Opening | IndexState::ColdIndexing { .. } => {
                        "The registered Atlas index is preparing its first snapshot"
                    }
                    IndexState::Suspended { .. } => {
                        "The registered Atlas index is suspended; inspect its retained status error"
                    }
                    IndexState::Draining | IndexState::Closed => {
                        "The registered Atlas index has closed reader admission"
                    }
                    _ => "The registered Atlas index has no readable published epoch",
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
