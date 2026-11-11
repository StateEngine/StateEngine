//! Project removal plans against bounded owner reads. Tombstones release only
//! registration/root lookup; no repository, transcript or history is erased.
use super::{
    process_commit,
    stop_plan::{self, ControlAgent},
};
use crate::{commit::Cx, dispatch::Kernel, scope, store_error::store_error};
use se_store::{Actor, AtomicBatch, EventBody, Expected, InputText, ProjectionRecord, Snapshot};
use se_types::{EventId, IdempotencyKey, Named, NativePath, ProjectId, Result, SeError};

pub struct RemovalInventory {
    pub project: ProjectionRecord,
    pub root: NativePath,
    pub agents: Vec<ControlAgent>,
    pub integrations: Vec<ProjectionRecord>,
}
pub fn inventory<R: Snapshot>(
    project: Named<ProjectId>,
    cx: &mut Cx<'_, R>,
) -> Result<RemovalInventory> {
    let head = scope::require_present(
        cx.read
            .project(project.id.clone())
            .map_err(|e| store_error(&e))?,
        "removal project",
        "Select a registered project in this data home.",
    )?;
    let original = head.original.as_deref().unwrap_or(&head.current);
    let owner = match &original.body {
        EventBody::ProjectRegistered { owner, .. } => owner,
        _ => {
            return Err(scope::unreadable(
                "removal owner",
                "original registration is unavailable",
            ));
        }
    };
    if !matches!(&cx.admission.actor, Actor::Human(actor) if actor==owner) {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "project.remove".into(),
            },
        )));
    }
    let root = match &head.current.body {
        EventBody::ProjectRegistered { roots, .. } | EventBody::ProjectUpdated { roots, .. } => {
            roots
                .first()
                .map(|r| r.path.clone())
                .ok_or_else(|| scope::unreadable("removal project", "no registered root"))?
        }
        EventBody::ProjectMoved { to, .. } => to.path.clone(),
        _ => {
            return Err(SeError::invalid(
                "removal project",
                "an active registration",
            ));
        }
    };
    let agents = stop_plan::agents(project, cx)?;
    let integrations = pages(cx, |cx, budget| {
        cx.read.integrations(budget).map_err(|e| store_error(&e))
    })?;
    Ok(RemovalInventory {
        project: head,
        root,
        agents,
        integrations,
    })
}
/// Read after stopping: the stop itself may settle an in-flight notice.
pub fn pending_effects<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<Vec<ProjectionRecord>> {
    pages(cx, |cx, budget| {
        cx.read.pending_effects(budget).map_err(|e| store_error(&e))
    })
}
/// Only mail notifications become obsolete when the owner removes a project.
/// Durable messages and recipient dispositions are independent and untouched.
pub fn is_mail_notification(record: &ProjectionRecord) -> bool {
    notification_effect(record).is_some()
}
fn notification_effect(record: &ProjectionRecord) -> Option<se_store::RecordId> {
    let original = record.original.as_deref().unwrap_or(&record.current);
    match &original.body {
        EventBody::EffectRequested {
            effect,
            kind: se_store::EffectKind::Bell,
            intent:
                se_store::EffectIntent::MailNotice(_)
                | se_store::EffectIntent::Mail {
                    recipient: Actor::Agent(_),
                    ..
                },
            ..
        } => Some(*effect),
        _ => None,
    }
}
pub fn abandon_notification<R: Snapshot>(
    kernel: &Kernel,
    key: &IdempotencyKey,
    record: ProjectionRecord,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let effect = notification_effect(&record)
        .ok_or_else(|| SeError::invalid("removal notification", "an agent mail notification"))?;
    process_commit::batch(
        kernel,
        "project.remove",
        process_commit::phase_key(key, &format!("notification/{effect:?}/abandon"))?,
        serde_json::json!({"effect":effect,"phase":"abandon-notification"}),
        vec![EventBody::EffectSettled {
            effect,
            expected: Expected::Revision(record.revision),
            outcome: se_store::EffectOutcome::Abandoned,
            evidence: vec![],
            failure: Some("Owner project removal stopped the agents; this notification is abandoned, without claiming delivery or reading its retained mail.".into()),
            attempts: 0,
        }],
        cx,
    )
}
fn pages<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    read: impl Fn(&mut Cx<'_, R>, se_store::ReadBudget) -> Result<se_types::Page<ProjectionRecord>>,
) -> Result<Vec<ProjectionRecord>> {
    let mut records = Vec::new();
    let mut after = None;
    for _ in 0..64 {
        let page = read(cx, stop_plan::budget(after)?)?;
        records.extend(page.items().iter().cloned());
        if let Some(next) = page.next() {
            after = Some(next.clone());
            continue;
        }
        if !page.window().complete() {
            return Err(scope::unreadable(
                "removal inventory",
                "the finite window is incomplete",
            ));
        }
        return Ok(records);
    }
    Err(scope::unreadable(
        "removal inventory",
        "more than 6400 records; preserve the registration and reconcile this project first",
    ))
}
pub fn tombstone<R: Snapshot>(
    kernel: &Kernel,
    key: &IdempotencyKey,
    project: ProjectId,
    expected: se_store::Revision,
    witnesses: Vec<EventId>,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    if witnesses.is_empty() || witnesses.len() > 64 {
        return Err(SeError::invalid(
            "removal witnesses",
            "one to 64 committed outside-effect references",
        ));
    }
    process_commit::batch(
        kernel,
        "project.remove",
        process_commit::phase_key(key, &format!("{project}/tombstone"))?,
        serde_json::json!({"project":project,"phase":"tombstone"}),
        vec![EventBody::ProjectRemoved {
            project,
            expected: Expected::Revision(expected),
            witnesses,
            preserved: vec![
                "history".into(),
                "repo-files".into(),
                "git-history".into(),
                "provider-transcripts".into(),
                "backups".into(),
            ],
        }],
        cx,
    )
}
/// --keep-integrations preserves bytes and explicitly records that this
/// project's registration no longer owns their future maintenance.
pub fn keep_integration<R: Snapshot>(
    kernel: &Kernel,
    key: &IdempotencyKey,
    head: ProjectionRecord,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let EventBody::IntegrationRecorded {
        integration,
        path,
        key: entry,
        marker,
        prior_sha256,
        written_sha256,
        ..
    } = head.current.body
    else {
        return Err(scope::unreadable(
            "owned integration",
            "wrong projection kind",
        ));
    };
    process_commit::batch(
        kernel,
        "project.remove",
        process_commit::phase_key(key, &format!("integration/{integration:?}/keep"))?,
        serde_json::json!({"integration":integration,"phase":"keep-by-flag"}),
        vec![EventBody::<InputText>::IntegrationRecorded {
            integration,
            path,
            key: entry,
            marker,
            prior_sha256,
            written_sha256,
            state: se_store::IntegrationState::Conflict,
            witness: head.current.header.event,
            expected: Expected::Revision(head.revision),
        }],
        cx,
    )
}

pub fn integration_effect(
    key: &IdempotencyKey,
    id: se_store::RecordId,
) -> Result<se_store::RecordId> {
    use se_store::RecordIdentity;
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"remove-integration-v1\0");
    hash.update(key.as_str());
    hash.update(id.as_bytes());
    let mut bytes = *id.as_bytes();
    bytes[6..].copy_from_slice(&hash.finalize()[..10]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    se_store::RecordId::from_bytes(bytes).map_err(|e| store_error(&e))
}
pub fn integration_request<R: Snapshot>(
    kernel: &Kernel,
    key: &IdempotencyKey,
    head: &ProjectionRecord,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    use sha2::{Digest, Sha256};
    let EventBody::IntegrationRecorded { integration, .. } = &head.current.body else {
        return Err(scope::unreadable(
            "integration intention",
            "wrong projection",
        ));
    };
    let effect = integration_effect(key, *integration)?;
    let digest = Sha256::digest(
        serde_json::to_vec(&serde_json::json!({"integration":integration,"event":head.current.header.event,"revision":head.revision.value.get()}))
            .map_err(|e| scope::unreadable("integration intention", &e.to_string()))?,
    )
    .into();
    let request_key =
        process_commit::phase_key(key, &format!("integration/{integration:?}/reverse"))?;
    process_commit::batch(
        kernel,
        "project.remove",
        request_key.clone(),
        serde_json::json!({"integration":integration,"phase":"reverse-intent"}),
        vec![EventBody::EffectRequested {
            principal: Some(cx.admission.actor.clone()),
            effect,
            kind: se_store::EffectKind::IntegrationWrite,
            intent: se_store::EffectIntent::Integration {
                integration: *integration,
                plan_sha256: digest,
            },
            cause: head.current.header.event.clone(),
            request_key,
        }],
        cx,
    )
}
pub struct IntegrationSettlement {
    pub prior: ProjectionRecord,
    pub request: EventId,
    pub effect_revision: se_store::Revision,
    pub state: se_store::IntegrationState,
    pub observed_hash: Option<[u8; 32]>,
    pub failure: Option<String>,
}
pub fn settle_integration<R: Snapshot>(
    kernel: &Kernel,
    key: &IdempotencyKey,
    value: IntegrationSettlement,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let EventBody::IntegrationRecorded {
        integration,
        path,
        key: entry,
        marker,
        prior_sha256,
        ..
    } = value.prior.current.body
    else {
        return Err(scope::unreadable(
            "integration settlement",
            "wrong projection",
        ));
    };
    let effect = integration_effect(key, integration)?;
    let recorded = kernel.facts()?.event.clone();
    let outcome = if value.failure.is_some() {
        se_store::EffectOutcome::Failed
    } else {
        se_store::EffectOutcome::Witnessed
    };
    process_commit::batch(
        kernel,
        "project.remove",
        process_commit::phase_key(key, &format!("integration/{integration:?}/settle"))?,
        serde_json::json!({"integration":integration,"phase":"settle"}),
        vec![
            EventBody::IntegrationRecorded {
                integration,
                path,
                key: entry,
                marker,
                prior_sha256,
                written_sha256: value.observed_hash,
                state: value.state,
                witness: value.request,
                expected: Expected::Revision(value.prior.revision),
            },
            EventBody::EffectSettled {
                effect,
                expected: Expected::Revision(value.effect_revision),
                outcome,
                evidence: vec![recorded],
                failure: value.failure,
                attempts: 1,
            },
        ],
        cx,
    )
}
