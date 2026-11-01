//! Setup identity batches. Native directory/configuration publication belongs
//! to the CLI adapter; each admission retains its registry or project scope.
use crate::{commit::Cx, dispatch::Kernel, scope};
use se_store::{Actor, AtomicBatch, EventBody, Expected, PrincipalKind, Root, Scope, Snapshot};
use se_types::{IdempotencyKey, ProjectId, Result, SeError};

pub fn owner<R: Snapshot>(
    kernel: &Kernel,
    key: IdempotencyKey,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let Actor::Human(owner) = &cx.admission.actor else {
        return Err(SeError::invalid(
            "setup owner",
            "a natively admitted human owner",
        ));
    };
    if cx.admission.session.is_some() {
        return Err(SeError::invalid(
            "setup owner",
            "owner authority without a session",
        ));
    }
    let event = kernel.event(
        EventBody::PrincipalRegistered {
            principal: cx.admission.actor.clone(),
            kind: PrincipalKind::Human,
            owner: owner.clone(),
            created_by: None,
            name: "owner".into(),
            role: "owner".into(),
            expected: Expected::Absent,
        },
        cx,
    )?;
    kernel.batch(
        "project.init.owner",
        key,
        serde_json::json!({"owner":owner}),
        event,
        cx,
    )
}
pub fn register<R: Snapshot>(
    kernel: &Kernel,
    input: &super::ProjectInit,
    project: ProjectId,
    name: String,
    roots: Vec<Root>,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    if cx.admission.scope != Scope::Registry || cx.admission.session.is_some() {
        return Err(SeError::invalid(
            "project registration",
            "registry owner admission",
        ));
    }
    let Actor::Human(owner) = &cx.admission.actor else {
        return Err(SeError::invalid(
            "project registration",
            "a natively admitted human owner",
        ));
    };
    if roots.is_empty() {
        return Err(SeError::invalid(
            "repository roots",
            "a canonical native root",
        ));
    }
    let intent = serde_json::json!({"input":input,"roots":roots,"name":name});
    let event = kernel.event(
        EventBody::ProjectRegistered {
            project,
            name,
            roots,
            owner: owner.clone(),
            history_from: None,
            expected: Expected::Absent,
        },
        cx,
    )?;
    kernel.batch(
        "project.init",
        input.idempotency_key.clone(),
        intent,
        event,
        cx,
    )
}
pub fn saved_profile(
    configuration: &crate::config_policy::ConfigFile,
    row: &super::AgentRow,
) -> Result<crate::config_policy::ResolvedProfile> {
    configuration
        .resolve_profile(&row.profile, row.provider, false)
        .map_err(|error| scope::unreadable("initial agent saved profile", &error.to_string()))
}

/// Recover the actual project from its retained FULL registration receipt.
/// A replay never substitutes the fresh ID allocated by a later retry.
pub fn committed_registration<R: Snapshot>(
    receipt: &se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<ProjectId> {
    let event = super::receipt::committed_event(cx.read, receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "setup registration receipt",
            "committed scope or actor differs",
        ));
    }
    let EventBody::ProjectRegistered { project, .. } = event.body else {
        return Err(scope::unreadable(
            "setup registration receipt",
            "primary event is not a project registration",
        ));
    };
    let current = scope::require_present(
        cx.read
            .project(project.clone())
            .map_err(|e| crate::store_error::store_error(&e))?,
        "retained initialized project",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    if !matches!(
        current.current.body,
        EventBody::ProjectRegistered { .. } | EventBody::ProjectUpdated { .. }
    ) {
        return Err(scope::unreadable(
            "retained initialized project",
            "the original project is no longer active; a new setup intent requires a new key",
        ));
    }
    Ok(project)
}
