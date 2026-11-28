//! Live project registration through a running host's authoritative writer.
//! Shares setup policy with direct CLI setup via `se_core::ops::project`.
use super::{
    CommittedWrite, ExecutionContext, executor, failure::WriteIdentity, start::allocate_facts,
    submit,
};
use crate::client::lease::Deadline;
use se_core::{
    admission::{HumanTerminal, read_scope},
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops::{
        AgentCommand, AgentOutcome, AnyOutput, InitOutcome, NextStep, ProjectInit,
        inputs::Validate, project,
    },
    scope,
    store_error::store_error,
};
use se_store::{Actor, Admission, CommitState, Root, Scope, Snapshot};
use se_types::{
    AgentId, EventId, HumanId, IdempotencyKey, NativePath, ProjectId, Read, Result, SeError,
};
use std::path::PathBuf;

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

fn partial_commit_error(
    mut error: SeError,
    committed: &[String],
    id: &ProjectId,
    key: &IdempotencyKey,
) -> SeError {
    if !committed.is_empty() {
        error.body = error.body.with_remedy(se_types::Remedy {
            text: format!(
                "Earlier setup steps already committed for project {id} ({}). Resolve the failure and retry `se init` with the exact same `--key {key}` to resume.",
                committed.join(", "),
            ),
            command: None,
        });
    }
    error
}

fn resolve_root_and_name(input: &ProjectInit) -> Result<(NativePath, PathBuf, String)> {
    let (root, repo_path) = match (&input.native_root, &input.repo) {
        (Some(root), _) => (root.clone(), root.to_local()?),
        (None, Some(repo)) => {
            let path = PathBuf::from(repo);
            (NativePath::from_local(path.clone())?, path)
        }
        (None, None) => {
            return Err(SeError::invalid(
                "project.init repo",
                "a canonical repository root",
            ));
        }
    };
    let project_name = input
        .resolved_name
        .clone()
        .or_else(|| input.name.clone())
        .or_else(|| {
            repo_path
                .file_name()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .ok_or_else(|| SeError::invalid("project name", "a validated project name"))?;
    Ok((root, repo_path, project_name))
}

#[derive(Default)]
struct InitProgress {
    changed: Vec<String>,
    events: Vec<EventId>,
}

async fn ensure_project(
    context: &ExecutionContext,
    admission: &Admission,
    input: &ProjectInit,
    project_name: &str,
    root: &NativePath,
    deadline: &Deadline,
    progress: &mut InitProgress,
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
                    project::find_registered_project(&mut snap, &reg_input, &reg_name, &reg_root)?
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
            progress.events.extend(receipt.events.iter().cloned());
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
                progress.changed.push("registered the project".into());
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
    progress: &mut InitProgress,
) -> Result<()> {
    let owner_admission = project_admission.clone();
    let owner_key = project::phase_key(&input.idempotency_key, &format!("project-owner-{id}"))?;
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
        let receipt = submit::submit(context, batch, &identity, deadline).await?;
        progress.events.extend(receipt.events.iter().cloned());
        progress.changed.push("registered the project owner".into());
    }
    Ok(())
}

async fn ensure_initial_agent(
    context: &ExecutionContext,
    project_admission: &Admission,
    input: &ProjectInit,
    configuration: &se_config::config_policy::ConfigFile,
    deadline: &Deadline,
    progress: &mut InitProgress,
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
                if let Some(existing) = project::find_saved_agent(&mut snap, &agent_input.agent)? {
                    return Ok(Ok((existing, false)));
                }
                let plan_kernel =
                    Kernel::new(allocate_facts()?)?.with_configuration(agent_config)?;
                let op = project::initial_agent_op(&agent_input)?;
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
            progress.events.extend(receipt.events.iter().cloned());
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
                progress
                    .changed
                    .push("created the initial saved agent".into());
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
) -> Result<(se_store::ProjectionRecord, String, se_core::ops::AgentRow)> {
    let read_admission = project_admission.clone();
    let read_id = id.clone();
    let read_agent = agent_id.clone();
    context
        .run_foreground(deadline, move |ctx| {
            let phase = executor::checked_pooled_phase(&ctx.reads, ctx.generation)?;
            let mut snap = phase
                .into_snapshot(read_scope(&read_admission))
                .map_err(|e| store_error(&e))?;
            let result = (|| {
                let (metadata, project_name) = project::read_project_metadata(&mut snap, &read_id)?;
                let row = project::read_saved_agent(
                    &mut Cx {
                        read: &mut snap,
                        admission: &read_admission,
                    },
                    &read_agent,
                )?;
                Ok((metadata, project_name, row))
            })();
            executor::close_read(result, snap.close())
        })
        .await
}

struct FinalizeArgs {
    id: ProjectId,
    created: bool,
    project_name: String,
    metadata: se_store::ProjectionRecord,
    row: se_core::ops::AgentRow,
    agent_created: bool,
    human: HumanId,
    home: PathBuf,
    repo_path: PathBuf,
    key: IdempotencyKey,
    progress: InitProgress,
}

fn finish_output(
    args: FinalizeArgs,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<(AnyOutput, Option<CommittedWrite>)> {
    let next = AgentCommand::launch_in_home(&args.row.id, &args.home, &args.id, true)
        .map(|command| NextStep {
            text: "Launch your first agent".into(),
            command: command.command,
            argv: command.argv,
        })
        .ok_or_else(|| scope::unreadable("first launch command", AgentCommand::HOME_UNAVAILABLE))?;
    let output = project::build_init_output(
        project::InitOutputParts {
            id: args.id,
            outcome: if args.created {
                InitOutcome::Created
            } else {
                InitOutcome::AlreadyPresent
            },
            project_name: args.project_name,
            metadata: args.metadata,
            row: args.row,
            agent_created: args.agent_created,
            human: args.human,
            os_user: String::new(),
            home: args.home.display().to_string(),
            repo_root: args.repo_path.display().to_string(),
            git: None,
            import_hint: None,
            native_server_port: 0,
            idempotency_key: args.key.clone(),
            changed: args.progress.changed,
            next,
        },
        configuration,
    )?
    .into();
    let committed = (!args.progress.events.is_empty()).then(|| CommittedWrite {
        operation: "project.init".into(),
        key: Some(args.key),
        natural_events: Vec::new(),
        committed_events: args.progress.events,
    });
    Ok((output, committed))
}

pub(super) async fn execute(
    context: ExecutionContext,
    input: ProjectInit,
    admission: Admission,
    kernel: Kernel,
    deadline: &Deadline,
) -> Result<(AnyOutput, Option<CommittedWrite>)> {
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
    input.validate()?;
    let (root, repo_path, project_name) = resolve_root_and_name(&input)?;
    let configuration = kernel.configuration().cloned().unwrap_or_default();
    if input.harness.is_some() {
        se_core::harness_selection::resolve(
            &configuration,
            input.provider,
            input.harness.as_deref(),
        )?;
    }
    let mut progress = InitProgress::default();
    let (id, created) = ensure_project(
        &context,
        &admission,
        &input,
        &project_name,
        &root,
        deadline,
        &mut progress,
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
        &mut progress,
    )
    .await
    .map_err(|err| partial_commit_error(err, &progress.changed, &id, &input.idempotency_key))?;
    let (agent_id, agent_created) = ensure_initial_agent(
        &context,
        &project_admission,
        &input,
        &configuration,
        deadline,
        &mut progress,
    )
    .await
    .map_err(|err| partial_commit_error(err, &progress.changed, &id, &input.idempotency_key))?;
    let (metadata, project_name, row) =
        read_final_state(&context, &project_admission, &id, &agent_id, deadline)
            .await
            .map_err(|err| {
                partial_commit_error(err, &progress.changed, &id, &input.idempotency_key)
            })?;
    project::verify_saved_agent(&row, &input)
        .map_err(|err| partial_commit_error(err, &progress.changed, &id, &input.idempotency_key))?;
    finish_output(
        FinalizeArgs {
            id,
            created,
            project_name,
            metadata,
            row,
            agent_created,
            human,
            home: context.state_directory,
            repo_path,
            key: input.idempotency_key,
            progress,
        },
        &configuration,
    )
}
