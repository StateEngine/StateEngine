//! Finish the separate registry/project setup admissions and read their effects.
use super::*;
pub(super) fn finish(
    cx: &Bootstrap,
    input: &ProjectInit,
    repository: &repository::Repository,
    observed: &owner::FileOwner,
    store: &mut SqliteDirect,
    lease: &DirectLease,
    mut changed: Vec<String>,
) -> Result<AnyOutput> {
    let inventory = owner::inventory(store, &lease.files)?;
    let human = match inventory.owners.as_slice() {
        [owner] => owner.clone(),
        [] => HumanId::from_bytes(
            execute::facts()?
                .message
                .canonical_bytes()?
                .ok_or_else(|| SeError::invalid("owner identity", "fresh canonical UUID"))?,
        )?,
        _ => {
            return Err(scope::unreadable(
                "setup owner",
                "multiple durable owners cannot be resolved automatically",
            ));
        }
    };
    let mut admission = Admission {
        actor: Actor::Human(human.clone()),
        scope: Scope::Registry,
        session: None,
        generation: 1,
    };
    if !present(store, &admission, admission.actor.clone())? {
        let kernel = Kernel::new(execute::facts()?)?;
        let mut snap = store
            .snapshot(read_scope(&admission))
            .map_err(|e| store_error(&e))?;
        let batch = project::owner(
            &kernel,
            phase_key(&input.idempotency_key, "registry-owner")?,
            &mut Cx {
                read: &mut snap,
                admission: &admission,
            },
        );
        snap.close().map_err(|e| store_error(&e))?;
        append(store, lease, batch?, &mut changed)?;
        changed.push("registered the home owner".into());
    }
    let root = NativePath::from_local(repository.path.clone())?;
    let mut found = None;
    for record in select::projects(store, &admission)? {
        let (id, registered, roots) = match &record.current.body {
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
            } => (project, name, roots),
            _ => continue,
        };
        if roots.iter().any(|candidate| candidate.path == root) {
            if found.is_some() {
                return Err(scope::unreadable(
                    "setup project",
                    "repository has more than one registration",
                ));
            }
            if input.name.is_some() && registered != &repository.name {
                return Err(SeError::invalid(
                    "project name",
                    "the existing registered name for this repository",
                ));
            }
            found = Some(id.clone());
        }
    }
    let created = found.is_none();
    let id = match found {
        Some(id) => id,
        None => {
            let id =
                ProjectId::from_bytes(execute::facts()?.message.canonical_bytes()?.ok_or_else(
                    || SeError::invalid("project identity", "fresh canonical UUID"),
                )?)?;
            let kernel = Kernel::new(execute::facts()?)?;
            let mut snap = store
                .snapshot(read_scope(&admission))
                .map_err(|e| store_error(&e))?;
            let canonical_key = serde_json::to_vec(&root)
                .map_err(|e| scope::unreadable("repository native identity", &e.to_string()))?;
            let batch = project::register(
                &kernel,
                input,
                id.clone(),
                repository.name.clone(),
                vec![se_store::Root {
                    path: root,
                    canonical_key,
                }],
                &mut Cx {
                    read: &mut snap,
                    admission: &admission,
                },
            );
            snap.close().map_err(|e| store_error(&e))?;
            let committed = append(store, lease, batch?, &mut changed)?;
            let mut snap = store
                .snapshot(read_scope(&admission))
                .map_err(|e| store_error(&e))?;
            let event = project::committed_registration(
                &committed,
                &mut Cx {
                    read: &mut snap,
                    admission: &admission,
                },
            );
            let closed = snap.close().map_err(|e| store_error(&e));
            let event = match event {
                Ok(event) => {
                    closed?;
                    event
                }
                Err(error) => {
                    return Err(match closed {
                        Ok(()) => error,
                        Err(close) => error.with_cause(close),
                    });
                }
            };
            let project = event;
            if committed.state == se_store::CommitState::Committed {
                changed.push("registered the project".into());
            }
            project
        }
    };
    admission.scope = Scope::Project(id.clone());
    if !present(store, &admission, admission.actor.clone())? {
        let kernel = Kernel::new(execute::facts()?)?;
        let mut snap = store
            .snapshot(read_scope(&admission))
            .map_err(|e| store_error(&e))?;
        let batch = project::owner(
            &kernel,
            phase_key(&input.idempotency_key, &format!("project-owner-{id}"))?,
            &mut Cx {
                read: &mut snap,
                admission: &admission,
            },
        );
        snap.close().map_err(|e| store_error(&e))?;
        append(store, lease, batch?, &mut changed)?;
        changed.push("registered the project owner".into());
    }
    let (agent, agent_created) = agent_setup::initial_agent(cx, input, store, lease, &admission)?;
    let (port, config_changed) =
        crate::route::init_config::listener_port(cx, &lease.files, observed.os_owner())?;
    if agent_created {
        changed.push("created the initial saved agent".into());
    }
    if config_changed {
        changed.push("persisted the initial listener port".into());
    }
    let mut snap = store
        .snapshot(read_scope(&admission))
        .map_err(|e| store_error(&e))?;
    let metadata = scope::require_present(
        snap.project(id.clone()).map_err(|e| store_error(&e))?,
        "initialized project",
        "Read the original project metadata in this data home, then retry se init with its original --key; preserve existing project and machine identities.",
    )?;
    snap.close().map_err(|e| store_error(&e))?;
    let project_name = match &metadata.current.body {
        EventBody::ProjectRegistered { name, .. } | EventBody::ProjectUpdated { name, .. } => {
            name.clone()
        }
        _ => {
            return Err(scope::unreadable(
                "initialized project",
                "active project metadata is unavailable",
            ));
        }
    };
    let command = AgentCommand::launch_in_home(&agent.id, &cx.home, &id, false)
        .ok_or_else(|| scope::unreadable("first launch command", AgentCommand::HOME_UNAVAILABLE))?;
    let node_source = repository.path.join(".stateengine/projects.jsonl");
    let import_hint=match se_proc::NativeSourcePin::open(&node_source) {
        Ok(Some(_))=>Some("Node history detected. Preserve an immutable source copy, then run se import --from-node PATH.".into()),
        Ok(None)=>None,
        Err(error)=>Some(format!("Node history could not be inspected: {error}; preserve its source before importing.")),
    };
    Ok(InitOutput {
        import_hint,
        idempotency_key: input.idempotency_key.clone(),
        outcome: if created {
            if repository.nonempty || repository.git.is_some() {
                InitOutcome::Adopted
            } else {
                InitOutcome::Created
            }
        } else {
            InitOutcome::AlreadyPresent
        },
        project: ProjectView {
            id: id.clone(),
            name: project_name,
            root: repository.path.display().to_string(),
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
            root: repository.path.display().to_string(),
            git: repository.git.clone(),
            files_touched: 0,
        },
        owner: OwnerView {
            human_id: human.clone(),
            os_user: observed.os_owner().into(),
        },
        home: cx.home.display().to_string(),
        agent: InitialAgent {
            id: agent.id.clone(),
            name: agent.name.clone(),
            outcome: if agent_created {
                IdentityOutcome::Created
            } else {
                IdentityOutcome::Existing
            },
            provider: agent.provider,
            model: agent.model.clone(),
            permission_profile: project::saved_profile(&cx.config.value, &agent)?,
        },
        profile: InitProfile {
            schema: "stateengine-init/v1".into(),
            project: id.clone(),
            repo_root: repository.path.display().to_string(),
            registry_root: cx.home.display().to_string(),
            keys_dir: cx.home.display().to_string(),
            human_id: human,
            agent_id: agent.id.clone(),
            native_server_port: port,
        },
        integrations: vec![],
        changed,
        next: super::super::command_hint::next(command, "Launch your first agent"),
        launch: None,
    }
    .into())
}
