//! Finite owner reads and typed source row planning.
use super::node::NodeContext;
use super::{super::ExecutionContext, batch, read};
use se_core::{scope, store_error::store_error};
use se_store::*;
use se_types::{NativePath, Read, Result};
pub(super) struct Progress {
    pub checkpoint: Option<ImportCheckpoint>,
    pub counts: ImportCounts,
    pub deferred: u64,
}
pub(super) fn context(
    context: &ExecutionContext,
    admission: Admission,
    id: RecordId,
    source: SourceEvidence,
    now: i64,
) -> Result<NodeContext> {
    let store = read::snapshot(context, &admission, |r| Ok(r.info()))?;
    let owner_profiles = match context.custody.get() {
        Some(custody) => match custody.import_profiles() {
            Ok(value) => Read::Present { value },
            Err(error) => Read::Unreadable {
                source: "active owner profile configuration".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.into_body())),
            },
        },
        None => Read::Unknown {
            what:
                "active owner profile configuration is not available through a native coordinator"
                    .into(),
        },
    };
    Ok(NodeContext {
        admission,
        store,
        source,
        import: id,
        observed_at_us: now,
        owner_profiles,
        prerequisites_pending: false,
        human_mappings: Default::default(),
        human_names: Default::default(),
    })
}
pub(super) fn start(
    context: &ExecutionContext,
    cx: &NodeContext,
    source: NativePath,
) -> Result<Option<AtomicBatch>> {
    read::snapshot(context, &cx.admission, |r| {
        match r.import_run(cx.import).map_err(|e| store_error(&e))? {
            Read::Present { value } => {
                let first = value.original.as_deref().unwrap_or(&value.current);
                if !matches!(&first.body,EventBody::ImportStarted{source:actual,policy_version:2,format,..} if *actual==source && format=="node-user-history/v1")
                {
                    return Err(scope::unreadable(
                        "import source binding",
                        "the retained run has a different source or policy",
                    ));
                }
                Ok(None)
            }
            Read::Absent { .. } => Ok(Some(batch::start(cx, source)?)),
            Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
            Read::Unknown { what } => Err(scope::unreadable("import run", &what)),
        }
    })
}
pub(super) fn progress(
    context: &ExecutionContext,
    cx: &NodeContext,
    family: ImportFamily,
    key: &[u8],
) -> Result<Progress> {
    read::snapshot(context, &cx.admission, |r| {
        match r
            .import_source(cx.import, family, key)
            .map_err(|e| store_error(&e))?
        {
            Read::Present { value } => {
                let EventBody::ImportProgress {
                    mut checkpoint,
                    counts,
                } = value.current.body
                else {
                    return Err(scope::unreadable("import checkpoint", "head kind differs"));
                };
                checkpoint.expected = Expected::Revision(value.revision);
                Ok(Progress {
                    checkpoint: Some(checkpoint),
                    deferred: counts.deferred,
                    counts,
                })
            }
            Read::Absent { .. } => Ok(Progress {
                checkpoint: None,
                counts: ImportCounts::default(),
                deferred: 0,
            }),
            Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
            Read::Unknown { what } => Err(scope::unreadable("import checkpoint", &what)),
        }
    })
}
pub(super) fn finish(
    context: &ExecutionContext,
    cx: &NodeContext,
    counts: ImportCounts,
    complete: bool,
) -> Result<Option<AtomicBatch>> {
    read::snapshot(context, &cx.admission, |r| {
        let head = batch::required(
            r.import_run(cx.import).map_err(|e| store_error(&e))?,
            "import run",
        )?;
        if matches!(&head.current.body,EventBody::ImportFinished{counts:old,complete:done,..} if old==&counts && *done==complete)
        {
            return Ok(None);
        }
        batch::finish(
            cx,
            Expected::Revision(head.revision),
            counts,
            complete,
            Vec::new(),
        )
        .map(Some)
    })
}
pub(super) fn owner_project(
    context: &ExecutionContext,
    cx: &NodeContext,
) -> Result<Option<AtomicBatch>> {
    let present = read::snapshot(context, &cx.admission, |r| {
        match r
            .principal(cx.admission.actor.clone())
            .map_err(|e| store_error(&e))?
        {
            Read::Present { .. } => Ok(true),
            Read::Absent { .. } => Ok(false),
            Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
            Read::Unknown { what } => Err(scope::unreadable("import owner principal", &what)),
        }
    })?;
    if present {
        return Ok(None);
    }
    let mut global = cx.admission.clone();
    global.scope = Scope::Registry;
    let name = read::snapshot(context, &global, |r| {
        let owner = batch::required(
            r.principal(global.actor.clone())
                .map_err(|e| store_error(&e))?,
            "current protected home owner",
        )?;
        match owner.current.body {
            EventBody::PrincipalRegistered { name, .. }
            | EventBody::PrincipalRenamed { name, .. } => Ok(name),
            _ => Err(scope::unreadable(
                "current owner name",
                "registered owner metadata is missing",
            )),
        }
    })?;
    let Actor::Human(owner) = &cx.admission.actor else {
        return Err(scope::unreadable(
            "import owner",
            "a protected human owner is required",
        ));
    };
    let event = batch::event(
        cx,
        &format!("import:{:?}:current-owner", cx.import),
        EventBody::PrincipalRegistered {
            principal: cx.admission.actor.clone(),
            kind: PrincipalKind::Human,
            owner: owner.clone(),
            created_by: None,
            // This is a new current-owner adoption, not a source human name.
            // Give it its own label so the usual historical owner's identical
            // OS display name can retain its original ID and spelling.
            name: format!("Current owner ({name})"),
            role: "project owner".into(),
            expected: Expected::Absent,
        },
    )?;
    Ok(Some(batch::atomic(cx, vec![event], None)))
}

pub(super) fn tombstone(
    context: &ExecutionContext,
    cx: &NodeContext,
) -> Result<Option<AtomicBatch>> {
    read::snapshot(context, &cx.admission, |r| {
        let Scope::Project(project) = &cx.admission.scope else {
            return Err(scope::unreadable(
                "import removal",
                "project scope required",
            ));
        };
        let head = batch::required(
            r.project(project.clone()).map_err(|e| store_error(&e))?,
            "imported project registration",
        )?;
        if matches!(head.current.body, EventBody::ProjectRemoved { .. }) {
            return Ok(None);
        }
        let original = head.original.as_deref().unwrap_or(&head.current);
        if original.header.door != Door::Import {
            return Err(scope::unreadable(
                "import removal",
                "current registration is not adopted source history",
            ));
        }
        let event=batch::event(cx,&format!("import:{:?}:source-project-removed",cx.import),EventBody::ProjectRemoved{project:project.clone(),expected:Expected::Revision(head.revision),witnesses:vec![head.current.header.event],preserved:vec!["Imported user history and retained source copy; no process, provider account or credential was adopted".into()]})?;
        Ok(Some(batch::atomic(cx, vec![event], None)))
    })
}

pub(super) fn resume(
    context: &ExecutionContext,
    cx: &NodeContext,
) -> Result<Vec<se_core::ops::store_import::ImportResume>> {
    read::snapshot(context, &cx.admission, |r| {
        let mut after = None;
        let mut output = Vec::new();
        for _ in 0..64 {
            let page = r
                .sessions(ReadBudget {
                    page: se_types::PageRequest {
                        after,
                        limit: std::num::NonZeroU32::new(100)
                            .ok_or_else(|| scope::unreadable("session read bound", "zero limit"))?,
                        max_bytes: std::num::NonZeroU32::new(1024 * 1024)
                            .ok_or_else(|| scope::unreadable("session read bound", "zero bytes"))?,
                    },
                    deadline: std::time::Duration::from_millis(250),
                })
                .map_err(|e| store_error(&e))?;
            for session in page.items() {
                let original = session.original.as_deref().unwrap_or(&session.current);
                if original.header.door != Door::Import {
                    continue;
                }
                let EventBody::SessionPrepared {
                    session: session_id,
                    agent,
                    provider,
                    native_ref,
                    ..
                } = &original.body
                else {
                    return Err(scope::unreadable(
                        "imported session reference",
                        "original historical session metadata is absent",
                    ));
                };
                let provider = match provider {
                    Provider::Claude => "claude",
                    Provider::Codex => "codex",
                    Provider::SeCode => "secode",
                };
                let reference = (!native_ref.is_empty()).then(|| native_ref.clone());
                let unsupported = if native_ref.is_empty() {
                    match &original.header.cause {
                        Some(cause) => match batch::required(
                            r.event(cause.clone()).map_err(|e| store_error(&e))?,
                            "historical conversation provenance",
                        )?
                        .body
                        {
                            EventBody::LegacyRetained {
                                bytes: Some(bytes), ..
                            } => {
                                serde_json::from_slice::<serde_json::Value>(&bytes.bytes)
                                    .map_err(|e| {
                                        scope::unreadable(
                                            "historical reference state",
                                            &e.to_string(),
                                        )
                                    })?
                                    .get("native_reference_state")
                                    .and_then(serde_json::Value::as_str)
                                    == Some("unsupported")
                            }
                            _ => false,
                        },
                        None => false,
                    }
                } else {
                    false
                };
                output.push(se_core::ops::store_import::ImportResume {
                    session: session_id.to_string(),
                    agent: agent.to_string(),
                    provider: provider.into(),
                    native_reference: reference,
                    state: if unsupported {
                        "unsupported"
                    } else if native_ref.is_empty() {
                        "missing"
                    } else {
                        "retained"
                    }
                    .into(),
                });
            }
            if let Some(next) = page.next() {
                after = Some(next.clone());
                continue;
            }
            if !page.window().complete() {
                return Err(scope::unreadable(
                    "imported session references",
                    "finite session inventory is incomplete",
                ));
            }
            return Ok(output);
        }
        Err(scope::unreadable(
            "imported session references",
            "session inventory exceeds its 6400-record bound; no references were silently omitted",
        ))
    })
}
