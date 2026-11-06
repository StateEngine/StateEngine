//! Setup identity batches. Native directory/configuration publication belongs
//! to the CLI adapter; each admission retains its registry or project scope.
use crate::{commit::Cx, dispatch::Kernel, ops::inputs::Validate, scope};
use se_store::{
    Actor, AtomicBatch, EventBody, Expected, PrincipalKind, ProjectionRecord, Root, Scope, Snapshot,
};
use se_types::{IdempotencyKey, NativePath, ProjectId, Result, SeError};

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
pub struct ProjectMoveThen {
    pub(crate) request: IdempotencyKey,
    pub(crate) from: Vec<String>,
    pub(crate) to: String,
}
/// The recorded git identity the CLI adapter proved at the move target: the
/// marker's HEAD and branch, read back before the roots revision applies.
#[derive(Debug, Clone)]
pub struct MoveIdentity {
    pub head: Option<String>,
    pub branch: Option<String>,
}
fn bounded_identity(head: &Option<String>, branch: &Option<String>) -> Result<()> {
    if head.as_deref().is_some_and(|value| {
        !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err(SeError::invalid(
            "move identity",
            "the recorded 40 or 64 character git HEAD",
        ));
    }
    if branch
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > 256)
    {
        return Err(SeError::invalid("move identity", "a bounded branch name"));
    }
    Ok(())
}
/// Propose the roots table revision for a verified move. The CLI adapter
/// already proved the target's recorded git identity and owner admission;
/// the store re-enforces the door, scope, owner and live-custody rules.
pub fn move_root<R: Snapshot>(
    kernel: &Kernel,
    input: &super::ProjectMove,
    record: &ProjectionRecord,
    from: Vec<Root>,
    to: Root,
    identity: &MoveIdentity,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, ProjectMoveThen)> {
    input.validate()?;
    let project = scope::project(cx.admission)?;
    if cx.admission.session.is_some() {
        return Err(SeError::invalid(
            "project move admission",
            "owner admission without a session",
        ));
    }
    if !matches!(cx.admission.actor, Actor::Human(_)) {
        return Err(SeError::invalid(
            "project move actor",
            "a natively admitted human owner",
        ));
    }
    let original = record.original.as_deref().unwrap_or(&record.current);
    let EventBody::ProjectRegistered { name, .. } = &original.body else {
        return Err(SeError::invalid("project move", "a registered name"));
    };
    if from.is_empty() || from.len() > 64 {
        return Err(SeError::invalid("previous roots", "1..64 registered roots"));
    }
    if from.iter().any(|root| root.path == to.path) {
        return Err(SeError::invalid(
            "move target",
            "a folder different from the registered roots",
        ));
    }
    bounded_identity(&identity.head, &identity.branch)?;
    let intent = serde_json::json!({
        "input": input,
        "from": from,
        "to": to,
        "head": &identity.head,
        "branch": &identity.branch,
    });
    let event = kernel.event(
        EventBody::ProjectMoved {
            project: project.clone(),
            name: name.clone(),
            from: from.clone(),
            to: to.clone(),
            head: identity.head.clone(),
            branch: identity.branch.clone(),
            expected: Expected::Revision(record.revision),
        },
        cx,
    )?;
    let batch = kernel.batch(
        "project.move",
        input.idempotency_key.clone(),
        intent,
        event,
        cx,
    )?;
    let from_strings = from
        .iter()
        .map(|root| root.path.to_local().map(|path| path.display().to_string()))
        .collect::<Result<Vec<_>>>()?;
    let to_string = to.path.to_local().map(|path| path.display().to_string())?;
    Ok((
        batch,
        ProjectMoveThen {
            request: input.idempotency_key.clone(),
            from: from_strings,
            to: to_string,
        },
    ))
}
/// Read the committed move back: the same scope and actor, the primary event
/// body and the current named project.
pub fn move_committed<R: Snapshot>(
    then: ProjectMoveThen,
    receipt: se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::MoveOutput> {
    super::receipt::receipt_key(&receipt, &then.request, "project move receipt")?;
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "project move receipt",
            "committed scope/actor differs",
        ));
    }
    let commit = super::receipt::write_fields(&receipt, &event)?;
    let named = super::receipt::named_project(cx)?;
    let EventBody::ProjectMoved { head, branch, .. } = &event.body else {
        return Err(scope::unreadable(
            "project move receipt",
            "primary event is not a project move",
        ));
    };
    Ok(super::MoveOutput {
        commit,
        project: named,
        from: then.from,
        to: then.to,
        head: head.clone(),
        branch: branch.clone(),
    })
}
/// Re-read a committed move from its retained receipt. An idempotent retry
/// arrives after the move already applied, so the registered roots include
/// the target itself and the physical preflight would refuse the retry as a
/// copy. The committed body supplies the recorded from/to; the same scope,
/// actor, project and target as the original call must hold, and a key the
/// store retained for another intent is refused here, before any write.
pub fn move_replay<R: Snapshot>(
    project: &ProjectId,
    key: &IdempotencyKey,
    expected_target: &NativePath,
    receipt: se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::MoveOutput> {
    super::receipt::receipt_key(&receipt, key, "project move receipt")?;
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "project move receipt",
            "committed scope/actor differs",
        ));
    }
    let EventBody::ProjectMoved {
        project: moved,
        from,
        to,
        ..
    } = &event.body
    else {
        return Err(scope::unreadable(
            "project move receipt",
            "primary event is not a project move",
        ));
    };
    if moved != project {
        return Err(scope::unreadable(
            "project move receipt",
            "the request key is retained for a different project",
        ));
    }
    if &to.path != expected_target {
        return Err(scope::unreadable(
            "project move receipt",
            "the request key is retained for a different move target",
        ));
    }
    let then = ProjectMoveThen {
        request: key.clone(),
        from: from
            .iter()
            .map(|root| root.path.to_local().map(|path| path.display().to_string()))
            .collect::<Result<Vec<_>>>()?,
        to: to.path.to_local().map(|path| path.display().to_string())?,
    };
    move_committed(then, receipt, cx)
}
pub fn saved_profile(
    configuration: &crate::config_policy::ConfigFile,
    row: &super::AgentRow,
) -> Result<crate::config_policy::ResolvedProfile> {
    // Setup's first-launch command uses --detach. Resolve that same mode,
    // including Codex's sandboxed, escalation-denying headless default.
    configuration
        .resolve_profile(&row.profile, row.provider, true)
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
        EventBody::ProjectRegistered { .. }
            | EventBody::ProjectUpdated { .. }
            | EventBody::ProjectMoved { .. }
    ) {
        return Err(scope::unreadable(
            "retained initialized project",
            "the original project is no longer active; a new setup intent requires a new key",
        ));
    }
    Ok(project)
}
