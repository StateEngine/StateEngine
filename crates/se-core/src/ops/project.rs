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
            ephemeral: None,
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
    configuration: &se_config::config_policy::ConfigFile,
    row: &super::AgentRow,
) -> Result<se_config::config_policy::ResolvedProfile> {
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

/// Deterministic phase-scoped idempotency key derived from the caller's setup key.
pub fn phase_key(key: &IdempotencyKey, phase: &str) -> Result<IdempotencyKey> {
    use sha2::{Digest, Sha256};
    let digest = se_types::hex_lower(&Sha256::digest(
        serde_json::to_vec(key).map_err(|e| scope::unreadable("setup key", &e.to_string()))?,
    ));
    IdempotencyKey::new(format!("init.{phase}.{digest}"))
}

/// Active project identity, name and current roots, or `None` for non-active bodies.
pub fn active_project<T>(body: &EventBody<T>) -> Option<(&ProjectId, &str, &[Root])> {
    match body {
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
        } => Some((project, name.as_str(), roots.as_slice())),
        EventBody::ProjectMoved {
            project, name, to, ..
        } => Some((project, name.as_str(), std::slice::from_ref(to))),
        _ => None,
    }
}

fn setup_read_budget(after: Option<se_types::Cursor>) -> Result<se_store::ReadBudget> {
    use std::{num::NonZeroU32, time::Duration};
    Ok(se_store::ReadBudget {
        page: se_types::PageRequest {
            after,
            limit: NonZeroU32::new(100)
                .ok_or_else(|| SeError::invalid("setup page", "positive limit"))?,
            max_bytes: NonZeroU32::new(1024 * 1024)
                .ok_or_else(|| SeError::invalid("setup page", "positive byte budget"))?,
        },
        deadline: Duration::from_secs(1),
    })
}

/// The existing registration of `root` in the registry, if any.
pub fn find_registered_project<R: Snapshot>(
    snap: &mut R,
    input: &super::ProjectInit,
    project_name: &str,
    root: &NativePath,
) -> Result<Option<ProjectId>> {
    let mut after = None;
    let mut found = None;
    let mut complete = false;
    for _ in 0..64 {
        let page = snap
            .projects(setup_read_budget(after)?)
            .map_err(|e| crate::store_error::store_error(&e))?;
        for record in page.items() {
            let Some((id, registered, roots)) = active_project(&record.current.body) else {
                continue;
            };
            if roots.iter().any(|candidate| candidate.path == *root) {
                if found.is_some() {
                    return Err(scope::unreadable(
                        "setup project",
                        "repository has more than one registration",
                    ));
                }
                if input.name.is_some() && registered != project_name {
                    return Err(SeError::invalid(
                        "project name",
                        "the existing registered name for this repository",
                    ));
                }
                found = Some(id.clone());
            }
        }
        match page.next() {
            Some(next) => after = Some(next.clone()),
            None if page.window().complete() => {
                complete = true;
                break;
            }
            None => {
                return Err(scope::unreadable(
                    "setup project",
                    "project inventory is incomplete",
                ));
            }
        }
        if after.is_some() && page.items().is_empty() {
            return Err(scope::unreadable(
                "setup project",
                "nonprogressing project inventory",
            ));
        }
    }
    if !complete {
        return Err(scope::unreadable(
            "setup project",
            "project inventory exceeded its finite bound",
        ));
    }
    Ok(found)
}

/// Find an existing saved agent in the current project scope by name.
pub fn find_saved_agent<R: Snapshot>(
    snap: &mut R,
    agent_name: &str,
) -> Result<Option<se_types::AgentId>> {
    let mut after = None;
    let mut found = None;
    let mut complete = false;
    for _ in 0..64 {
        let page = snap
            .principals(setup_read_budget(after)?)
            .map_err(|e| crate::store_error::store_error(&e))?;
        for record in page.items() {
            if let EventBody::PrincipalRegistered {
                principal: Actor::Agent(agent),
                name,
                ..
            }
            | EventBody::PrincipalRenamed {
                principal: Actor::Agent(agent),
                name,
                ..
            } = &record.current.body
                && name == agent_name
                && found.replace(agent.clone()).is_some()
            {
                return Err(scope::unreadable(
                    "initial agent",
                    "saved name is ambiguous",
                ));
            }
        }
        match page.next() {
            Some(next) => after = Some(next.clone()),
            None if page.window().complete() => {
                complete = true;
                break;
            }
            None => {
                return Err(scope::unreadable(
                    "initial agent",
                    "principal inventory is incomplete",
                ));
            }
        }
        if after.is_some() && page.items().is_empty() {
            return Err(scope::unreadable(
                "initial agent",
                "nonprogressing principal inventory",
            ));
        }
    }
    if !complete {
        return Err(scope::unreadable(
            "initial agent",
            "principal inventory exceeded its finite bound",
        ));
    }
    Ok(found)
}

/// Verify an existing saved agent matches the requested provider and harness.
pub fn verify_saved_agent(row: &super::AgentRow, input: &super::ProjectInit) -> Result<()> {
    if input
        .provider
        .is_some_and(|provider| row.provider != provider)
    {
        return Err(SeError::invalid(
            "initial provider",
            "the existing agent keeps its saved provider; select a new --agent name to choose a different harness",
        ));
    }
    if input
        .harness
        .as_ref()
        .is_some_and(|selected| row.harness.as_ref() != Some(selected))
    {
        return Err(SeError::invalid(
            "initial harness",
            "the existing agent keeps its saved harness; create another agent with --harness to select a different one",
        ));
    }
    Ok(())
}

/// Build the `AgentCreate` operation for the initial saved agent.
pub fn initial_agent_op(input: &super::ProjectInit) -> Result<super::AnyOp> {
    Ok(super::AnyOp::AgentCreate(super::AgentCreate {
        provider_settings: Default::default(),
        harness: input.harness.clone(),
        name: input.agent.clone(),
        provider: input.provider,
        model: input.model.clone(),
        profile: None,
        idempotency_key: phase_key(&input.idempotency_key, "agent")?,
        external: false,
    }))
}

/// Read back an initialized project's active projection record and name.
pub fn read_project_metadata<R: Snapshot>(
    snap: &mut R,
    id: &ProjectId,
) -> Result<(ProjectionRecord, String)> {
    let metadata = scope::require_present(
        snap.project(id.clone())
            .map_err(|e| crate::store_error::store_error(&e))?,
        "initialized project",
        "Read the original project metadata in this data home, then retry se init with its original --key; preserve existing project and machine identities.",
    )?;
    let Some((_, project_name, _)) = active_project(&metadata.current.body) else {
        return Err(scope::unreadable(
            "initialized project",
            "active project metadata is unavailable",
        ));
    };
    let project_name = project_name.to_owned();
    Ok((metadata, project_name))
}

/// Read back the initial saved agent row.
pub fn read_saved_agent<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    agent: &se_types::AgentId,
) -> Result<super::AgentRow> {
    let output = super::agent_status::show(
        super::AgentShow {
            target_agent_id: Some(agent.clone()),
        },
        cx,
    )?;
    scope::require_present(
        output.agent,
        "initial saved agent",
        "Read the original saved agent in this data home, then retry se init with its original --key; preserve existing agent identities.",
    )
}

pub struct InitOutputParts {
    pub id: ProjectId,
    pub outcome: super::InitOutcome,
    pub project_name: String,
    pub metadata: ProjectionRecord,
    pub row: super::AgentRow,
    pub agent_created: bool,
    pub human: se_types::HumanId,
    pub os_user: String,
    pub home: String,
    pub repo_root: String,
    pub git: Option<super::GitView>,
    pub import_hint: Option<String>,
    pub native_server_port: u16,
    pub idempotency_key: IdempotencyKey,
    pub changed: Vec<String>,
    pub next: super::NextStep,
}

/// Shared `InitOutput` assembly used by both direct and live hosted setup.
pub fn build_init_output(
    parts: InitOutputParts,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<super::InitOutput> {
    let InitOutputParts {
        id,
        outcome,
        project_name,
        metadata,
        row,
        agent_created,
        human,
        os_user,
        home,
        repo_root,
        git,
        import_hint,
        native_server_port,
        idempotency_key,
        changed,
        next,
    } = parts;
    Ok(super::InitOutput {
        import_hint,
        idempotency_key,
        outcome,
        project: super::ProjectView {
            id: id.clone(),
            name: project_name,
            root: repo_root.clone(),
            registered_at: super::receipt::timestamp(
                metadata
                    .original
                    .as_deref()
                    .unwrap_or(&metadata.current)
                    .recorded_at_us,
            )?,
            git: None,
        },
        repo: super::RepositoryView {
            root: repo_root.clone(),
            git,
            files_touched: 0,
        },
        owner: super::OwnerView {
            human_id: human.clone(),
            os_user,
        },
        home: home.clone(),
        agent: super::InitialAgent {
            harness: row.harness.clone(),
            id: row.id.clone(),
            name: row.name.clone(),
            outcome: if agent_created {
                super::IdentityOutcome::Created
            } else {
                super::IdentityOutcome::Existing
            },
            provider: row.provider,
            model: row.model.clone(),
            permission_profile: saved_profile(configuration, &row)?,
        },
        profile: super::InitProfile {
            schema: "stateengine-init/v1".into(),
            project: id,
            repo_root,
            registry_root: home.clone(),
            keys_dir: home,
            human_id: human,
            agent_id: row.id,
            native_server_port,
        },
        integrations: vec![],
        changed,
        next,
        launch: None,
    })
}
