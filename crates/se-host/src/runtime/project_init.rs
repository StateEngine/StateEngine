//! Live project registration through a running host's authoritative writer.
//! Registers an additional project (or confirms an existing one) without
//! taking down active seats in other projects on the same home.
use super::{ExecutionContext, executor, failure::WriteIdentity, start::allocate_facts, submit};
use crate::client::lease::Deadline;
use se_core::{
    admission::{HumanTerminal, read_scope},
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops::{
        AgentCommand, AgentCreate, AgentOutcome, AgentRow, AgentShow, AnyOp, AnyOutput,
        IdentityOutcome, InitOutcome, InitOutput, InitProfile, InitialAgent, NextStep, OwnerView,
        ProjectInit, ProjectView, RepositoryView, agent_status, project, receipt,
    },
    scope,
    store_error::store_error,
};
use se_store::{
    Actor, Admission, CommitState, EventBody, ProjectionRecord, ReadBudget, Root, Scope, Snapshot,
    SqliteSnapshot,
};
use se_types::{
    AgentId, HumanId, IdempotencyKey, NativePath, PageRequest, ProjectId, Read, Result, SeError,
};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU32, path::PathBuf, time::Duration};

fn phase_key(key: &IdempotencyKey, phase: &str) -> Result<IdempotencyKey> {
    let digest = se_types::hex_lower(&Sha256::digest(
        serde_json::to_vec(key).map_err(|e| scope::unreadable("setup key", &e.to_string()))?,
    ));
    IdempotencyKey::new(format!("init.{phase}.{digest}"))
}

fn read_budget(after: Option<se_types::Cursor>) -> Result<ReadBudget> {
    Ok(ReadBudget {
        page: PageRequest {
            after,
            limit: NonZeroU32::new(100)
                .ok_or_else(|| SeError::invalid("project page", "positive limit"))?,
            max_bytes: NonZeroU32::new(1024 * 1024)
                .ok_or_else(|| SeError::invalid("project page", "positive byte budget"))?,
        },
        deadline: Duration::from_secs(1),
    })
}

fn active_project<T>(body: &EventBody<T>) -> Option<(&ProjectId, &str, &[Root])> {
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

fn find_registered_project(
    snap: &mut SqliteSnapshot,
    input: &ProjectInit,
    project_name: &str,
    root: &NativePath,
) -> Result<Option<ProjectId>> {
    let mut after = None;
    let mut found = None;
    let mut complete = false;
    for _ in 0..64 {
        let page = snap
            .projects(read_budget(after)?)
            .map_err(|e| store_error(&e))?;
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

fn find_saved_agent(snap: &mut SqliteSnapshot, agent_name: &str) -> Result<Option<AgentId>> {
    let mut after = None;
    let mut found = None;
    let mut complete = false;
    for _ in 0..64 {
        let page = snap
            .principals(read_budget(after)?)
            .map_err(|e| store_error(&e))?;
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

fn verify_saved_row(row: &AgentRow, input: &ProjectInit) -> Result<()> {
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

fn write_identity(batch: &se_store::AtomicBatch, operation: &'static str) -> WriteIdentity {
    WriteIdentity {
        operation,
        natural_key: None,
        key: batch.request.as_ref().map(|r| r.key.clone()),
        natural_events: if batch.request.is_none() {
            batch
                .events
                .iter()
                .map(|event| event.header.event.clone())
                .collect()
        } else {
            Vec::new()
        },
    }
}

async fn ensure_project(
    context: &ExecutionContext,
    admission: &Admission,
    input: &ProjectInit,
    project_name: &str,
    root: &NativePath,
    deadline: &Deadline,
    changed: &mut Vec<String>,
) -> Result<(ProjectId, bool)> {
    let reg_admission = admission.clone();
    let reg_input = input.clone();
    let reg_name = project_name.to_owned();
    let reg_root = root.clone();
    let planned = context
        .run_foreground(deadline, move |ctx| {
            let phase = executor::checked_pooled_phase(&ctx.reads, ctx.generation)?;
            let mut snap = phase
                .into_snapshot(read_scope(&reg_admission))
                .map_err(|e| store_error(&e))?;
            let result = (|| {
                if let Some(existing) =
                    find_registered_project(&mut snap, &reg_input, &reg_name, &reg_root)?
                {
                    return Ok(Ok(existing));
                }
                let id = ProjectId::from_bytes(
                    allocate_facts()?
                        .message
                        .canonical_bytes()?
                        .ok_or_else(|| {
                            SeError::invalid("project identity", "fresh canonical UUID")
                        })?,
                )?;
                let plan_kernel = Kernel::new(allocate_facts()?)?;
                let canonical_key = serde_json::to_vec(&reg_root)
                    .map_err(|e| scope::unreadable("repository native identity", &e.to_string()))?;
                let batch = project::register(
                    &plan_kernel,
                    &reg_input,
                    id,
                    reg_name,
                    vec![Root {
                        path: reg_root,
                        canonical_key,
                    }],
                    &mut Cx {
                        read: &mut snap,
                        admission: &reg_admission,
                    },
                )?;
                Ok(Err(batch))
            })();
            executor::close_read(result, snap.close())
        })
        .await?;
    match planned {
        Ok(existing) => Ok((existing, false)),
        Err(batch) => {
            let identity = write_identity(&batch, "project.init");
            let receipt = submit::submit(context, batch, &identity, deadline).await?;
            let committed_new = receipt.state == CommitState::Committed;
            let reg_admission = admission.clone();
            let id = context
                .run_foreground(deadline, move |ctx| {
                    let phase = executor::checked_pooled_phase(&ctx.reads, ctx.generation)?;
                    let mut snap = phase
                        .into_snapshot(read_scope(&reg_admission))
                        .map_err(|e| store_error(&e))?;
                    let result = project::committed_registration(
                        &receipt,
                        &mut Cx {
                            read: &mut snap,
                            admission: &reg_admission,
                        },
                    );
                    executor::close_read(result, snap.close())
                })
                .await?;
            if committed_new {
                changed.push("registered the project".into());
            }
            Ok((id, true))
        }
    }
}

async fn ensure_project_owner(
    context: &ExecutionContext,
    project_admission: &Admission,
    input: &ProjectInit,
    id: &ProjectId,
    deadline: &Deadline,
    changed: &mut Vec<String>,
) -> Result<()> {
    let owner_admission = project_admission.clone();
    let owner_key = phase_key(&input.idempotency_key, &format!("project-owner-{id}"))?;
    let maybe_batch = context
        .run_foreground(deadline, move |ctx| {
            let phase = executor::checked_pooled_phase(&ctx.reads, ctx.generation)?;
            let mut snap = phase
                .into_snapshot(read_scope(&owner_admission))
                .map_err(|e| store_error(&e))?;
            let result = (|| {
                match snap
                    .principal(owner_admission.actor.clone())
                    .map_err(|e| store_error(&e))?
                {
                    Read::Present { .. } => return Ok(None),
                    Read::Absent { .. } => {}
                    Read::Unreadable { source, reason, .. } => {
                        return Err(scope::unreadable(&source, &reason));
                    }
                    Read::Unknown { what } => {
                        return Err(scope::unreadable("setup principal", &what));
                    }
                }
                let plan_kernel = Kernel::new(allocate_facts()?)?;
                let batch = project::owner(
                    &plan_kernel,
                    owner_key,
                    &mut Cx {
                        read: &mut snap,
                        admission: &owner_admission,
                    },
                )?;
                Ok(Some(batch))
            })();
            executor::close_read(result, snap.close())
        })
        .await?;
    if let Some(batch) = maybe_batch {
        let identity = write_identity(&batch, "project.init.owner");
        submit::submit(context, batch, &identity, deadline).await?;
        changed.push("registered the project owner".into());
    }
    Ok(())
}

async fn ensure_initial_agent(
    context: &ExecutionContext,
    project_admission: &Admission,
    input: &ProjectInit,
    configuration: &se_config::config_policy::ConfigFile,
    deadline: &Deadline,
    changed: &mut Vec<String>,
) -> Result<(AgentId, bool)> {
    let agent_admission = project_admission.clone();
    let agent_input = input.clone();
    let agent_config = configuration.clone();
    let planned = context
        .run_foreground(deadline, move |ctx| {
            let phase = executor::checked_pooled_phase(&ctx.reads, ctx.generation)?;
            let mut snap = phase
                .into_snapshot(read_scope(&agent_admission))
                .map_err(|e| store_error(&e))?;
            let result = (|| {
                if let Some(existing) = find_saved_agent(&mut snap, &agent_input.agent)? {
                    return Ok(Ok((existing, false)));
                }
                let plan_kernel =
                    Kernel::new(allocate_facts()?)?.with_configuration(agent_config)?;
                let op = AnyOp::AgentCreate(AgentCreate {
                    provider_settings: Default::default(),
                    harness: agent_input.harness.clone(),
                    name: agent_input.agent.clone(),
                    provider: agent_input.provider,
                    model: agent_input.model.clone(),
                    profile: None,
                    idempotency_key: phase_key(&agent_input.idempotency_key, "agent")?,
                    external: false,
                });
                let terminal = HumanTerminal::Refused {
                    reason: "setup creates a safe saved identity without claiming human presence"
                        .into(),
                };
                match plan_kernel.plan(
                    op,
                    &mut Cx {
                        read: &mut snap,
                        admission: &agent_admission,
                    },
                    &terminal,
                )? {
                    OpStep::Complete(AnyOutput::AgentCreate(value)) => Ok(Ok((
                        value.value.agent.id,
                        value.value.outcome == AgentOutcome::Created,
                    ))),
                    OpStep::Commit { batch, then } => Ok(Err((batch, then, plan_kernel))),
                    _ => Err(scope::unreadable(
                        "initial agent",
                        "atomic identity/profile creation did not return a commit plan",
                    )),
                }
            })();
            executor::close_read(result, snap.close())
        })
        .await?;
    match planned {
        Ok(found) => Ok(found),
        Err((batch, then, plan_kernel)) => {
            let identity = write_identity(&batch, "agent.create");
            let receipt = submit::submit(context, batch, &identity, deadline).await?;
            let agent_admission = project_admission.clone();
            let (agent_id, created) = context
                .run_foreground(deadline, move |ctx| {
                    let phase = executor::checked_pooled_phase(&ctx.reads, ctx.generation)?;
                    let mut snap = phase
                        .into_snapshot(read_scope(&agent_admission))
                        .map_err(|e| store_error(&e))?;
                    let result = plan_kernel
                        .committed(
                            then,
                            receipt,
                            &mut Cx {
                                read: &mut snap,
                                admission: &agent_admission,
                            },
                        )
                        .and_then(|output| match output {
                            AnyOutput::AgentCreate(value) => Ok((
                                value.value.agent.id,
                                value.value.outcome == AgentOutcome::Created,
                            )),
                            _ => Err(scope::unreadable(
                                "initial agent",
                                "atomic identity/profile creation did not return its receipt",
                            )),
                        });
                    executor::close_read(result, snap.close())
                })
                .await?;
            if created {
                changed.push("created the initial saved agent".into());
            }
            Ok((agent_id, created))
        }
    }
}

async fn read_final_state(
    context: &ExecutionContext,
    project_admission: &Admission,
    id: &ProjectId,
    agent_id: &AgentId,
    deadline: &Deadline,
) -> Result<(ProjectionRecord, String, AgentRow)> {
    let read_admission = project_admission.clone();
    let project_id = id.clone();
    let agent_id = agent_id.clone();
    context
        .run_foreground(deadline, move |ctx| {
            let phase = executor::checked_pooled_phase(&ctx.reads, ctx.generation)?;
            let mut snap = phase
                .into_snapshot(read_scope(&read_admission))
                .map_err(|e| store_error(&e))?;
            let result = (|| {
                let metadata = scope::require_present(
                    snap.project(project_id.clone())
                        .map_err(|e| store_error(&e))?,
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
                let output = agent_status::show(
                    AgentShow {
                        target_agent_id: Some(agent_id),
                    },
                    &mut Cx {
                        read: &mut snap,
                        admission: &read_admission,
                    },
                )?;
                let row = scope::require_present(
                    output.agent,
                    "initial saved agent",
                    "Read the original saved agent in this data home, then retry se init with its original --key; preserve existing agent identities.",
                )?;
                Ok((metadata, project_name, row))
            })();
            executor::close_read(result, snap.close())
        })
        .await
}

struct OutputParts {
    id: ProjectId,
    created: bool,
    project_name: String,
    metadata: ProjectionRecord,
    row: AgentRow,
    agent_created: bool,
    human: HumanId,
    home: PathBuf,
    repo_path: PathBuf,
    idempotency_key: IdempotencyKey,
    changed: Vec<String>,
}

fn build_init_output(
    parts: OutputParts,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<AnyOutput> {
    let OutputParts {
        id,
        created,
        project_name,
        metadata,
        row,
        agent_created,
        human,
        home,
        repo_path,
        idempotency_key,
        changed,
    } = parts;
    let home_text = home.display().to_string();
    let repo_root = repo_path.display().to_string();
    let next = AgentCommand::launch_in_home(&row.id, &home, &id, true)
        .map(|command| NextStep {
            text: "Launch your first agent".into(),
            command: command.command,
            argv: command.argv,
        })
        .ok_or_else(|| scope::unreadable("first launch command", AgentCommand::HOME_UNAVAILABLE))?;
    Ok(InitOutput {
        import_hint: None,
        idempotency_key,
        outcome: if created {
            InitOutcome::Created
        } else {
            InitOutcome::AlreadyPresent
        },
        project: ProjectView {
            id: id.clone(),
            name: project_name,
            root: repo_root.clone(),
            registered_at: receipt::timestamp(
                metadata
                    .original
                    .as_deref()
                    .unwrap_or(&metadata.current)
                    .recorded_at_us,
            )?,
            git: None,
        },
        repo: RepositoryView {
            root: repo_root.clone(),
            git: None,
            files_touched: 0,
        },
        owner: OwnerView {
            human_id: human.clone(),
            os_user: String::new(),
        },
        home: home_text.clone(),
        agent: InitialAgent {
            harness: row.harness.clone(),
            id: row.id.clone(),
            name: row.name.clone(),
            outcome: if agent_created {
                IdentityOutcome::Created
            } else {
                IdentityOutcome::Existing
            },
            provider: row.provider,
            model: row.model.clone(),
            permission_profile: project::saved_profile(configuration, &row)?,
        },
        profile: InitProfile {
            schema: "stateengine-init/v1".into(),
            project: id,
            repo_root,
            registry_root: home_text.clone(),
            keys_dir: home_text,
            human_id: human,
            agent_id: row.id,
            native_server_port: 0,
        },
        integrations: vec![],
        changed,
        next,
        launch: None,
    }
    .into())
}

pub(super) async fn execute(
    context: ExecutionContext,
    input: ProjectInit,
    admission: Admission,
    kernel: Kernel,
    deadline: &Deadline,
) -> Result<AnyOutput> {
    let human: HumanId = match (&admission.actor, admission.session.is_none()) {
        (Actor::Human(owner), true) if admission.scope == Scope::Registry => owner.clone(),
        _ => {
            return Err(SeError::new(se_types::Detail::OwnerRequired(
                se_types::details::OwnerRequired {
                    op: "project.init".into(),
                },
            )));
        }
    };
    let repo_str = input
        .repo
        .as_deref()
        .ok_or_else(|| SeError::invalid("project.init repo", "a repository path"))?;
    let repo_path = PathBuf::from(repo_str);
    let root = NativePath::from_local(repo_path.clone())?;
    let project_name = match &input.name {
        Some(name) => name.clone(),
        None => repo_path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| SeError::invalid("project name", "a UTF-8 repository directory name"))?
            .to_owned(),
    };
    let configuration = kernel.configuration().cloned().unwrap_or_default();
    let mut changed = Vec::new();
    let (id, created) = ensure_project(
        &context,
        &admission,
        &input,
        &project_name,
        &root,
        deadline,
        &mut changed,
    )
    .await?;
    let project_admission = Admission {
        actor: Actor::Human(human.clone()),
        scope: Scope::Project(id.clone()),
        session: None,
        generation: admission.generation,
    };
    ensure_project_owner(
        &context,
        &project_admission,
        &input,
        &id,
        deadline,
        &mut changed,
    )
    .await?;
    let (agent_id, agent_created) = ensure_initial_agent(
        &context,
        &project_admission,
        &input,
        &configuration,
        deadline,
        &mut changed,
    )
    .await?;
    let (metadata, project_name, row) =
        read_final_state(&context, &project_admission, &id, &agent_id, deadline).await?;
    verify_saved_row(&row, &input)?;
    build_init_output(
        OutputParts {
            id,
            created,
            project_name,
            metadata,
            row,
            agent_created,
            human,
            home: context.state_directory,
            repo_path,
            idempotency_key: input.idempotency_key,
            changed,
        },
        &configuration,
    )
}
