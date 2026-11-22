//! Finish the separate registry/project setup admissions and read their effects.
use super::*;
pub(super) struct Plan<'a> {
    pub input: &'a ProjectInit,
    pub repository: &'a repository::Repository,
    pub configuration: &'a se_config::config_policy::ConfigFile,
}
pub(super) fn finish(
    cx: &Bootstrap,
    plan: Plan<'_>,
    observed: &owner::FileOwner,
    store: &mut SqliteDirect,
    lease: &DirectLease,
    mut changed: Vec<String>,
) -> Result<AnyOutput> {
    let Plan {
        input,
        repository,
        configuration,
    } = plan;
    let inventory = owner::inventory(store, &lease.files)?;
    let human = setup_owner(inventory.owners.as_slice())?;
    let mut admission = Admission {
        actor: Actor::Human(human.clone()),
        scope: Scope::Registry,
        session: None,
        generation: 1,
    };
    if ensure_owner(
        store,
        lease,
        &admission,
        input,
        "registry-owner",
        &mut changed,
    )? {
        changed.push("registered the home owner".into());
    }
    let root = NativePath::from_local(repository.path.clone())?;
    let found = registered_project(store, &admission, input, repository, &root)?;
    let created = found.is_none();
    let id = match found {
        Some(id) => id,
        None => register_project(
            store,
            lease,
            &admission,
            input,
            repository,
            root,
            &mut changed,
        )?,
    };
    // Record the git identity for future `se project move` verification.
    // Non-fatal: a repository without commits records nothing, and init never
    // fails because its move marker could not be written.
    record_git_identity(repository, &id, created, &mut changed);
    admission.scope = Scope::Project(id.clone());
    let phase = format!("project-owner-{id}");
    if ensure_owner(store, lease, &admission, input, &phase, &mut changed)? {
        changed.push("registered the project owner".into());
    }
    let (port, config_changed) = crate::route::init_config::listener_port(
        cx,
        &lease.files,
        observed.os_owner(),
        configuration,
    )?;
    let (agent, agent_created) =
        agent_setup::initial_agent(input, store, lease, &admission, configuration)?;
    if agent_created {
        changed.push("created the initial saved agent".into());
    }
    if config_changed {
        changed.push("persisted the setup configuration".into());
    }
    let (metadata, project_name) = project_metadata(store, &admission, &id)?;
    let command = AgentCommand::launch_in_home(&agent.id, &cx.home, &id, true)
        .ok_or_else(|| scope::unreadable("first launch command", AgentCommand::HOME_UNAVAILABLE))?;
    let import_hint = import_hint(repository);
    Ok(InitOutput {
        import_hint,
        idempotency_key: input.idempotency_key.clone(),
        outcome: outcome(created, repository),
        project: project_view(&id, project_name, repository, &metadata)?,
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
        agent: agent_view(&agent, agent_created, configuration)?,
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
fn setup_owner(owners: &[HumanId]) -> Result<HumanId> {
    match owners {
        [owner] => Ok(owner.clone()),
        [] => HumanId::from_bytes(
            execute::facts()?
                .message
                .canonical_bytes()?
                .ok_or_else(|| SeError::invalid("owner identity", "fresh canonical UUID"))?,
        ),
        _ => Err(scope::unreadable(
            "setup owner",
            "multiple durable owners cannot be resolved automatically",
        )),
    }
}
/// Register the admission's actor as an owner of its scope unless present;
/// true when this call registered it.
fn ensure_owner(
    store: &mut SqliteDirect,
    lease: &DirectLease,
    admission: &Admission,
    input: &ProjectInit,
    phase: &str,
    changed: &mut Vec<String>,
) -> Result<bool> {
    if present(store, admission, admission.actor.clone())? {
        return Ok(false);
    }
    let kernel = Kernel::new(execute::facts()?)?;
    let mut snap = super::super::select::open_snapshot(store, admission)?;
    let batch = project::owner(
        &kernel,
        phase_key(&input.idempotency_key, phase)?,
        &mut Cx {
            read: &mut snap,
            admission,
        },
    );
    snap.close().map_err(|e| store_error(&e))?;
    append(store, lease, batch?, changed)?;
    Ok(true)
}
/// The existing registration of this repository's root, if any.
fn registered_project(
    store: &SqliteDirect,
    admission: &Admission,
    input: &ProjectInit,
    repository: &repository::Repository,
    root: &NativePath,
) -> Result<Option<ProjectId>> {
    let mut found = None;
    for record in select::projects(store, admission)? {
        let Some((id, registered, roots)) = select::active_project(&record.current.body) else {
            continue;
        };
        if roots.iter().any(|candidate| candidate.path == *root) {
            if found.is_some() {
                return Err(scope::unreadable(
                    "setup project",
                    "repository has more than one registration",
                ));
            }
            if input.name.is_some() && registered != repository.name {
                return Err(SeError::invalid(
                    "project name",
                    "the existing registered name for this repository",
                ));
            }
            found = Some(id.clone());
        }
    }
    Ok(found)
}
fn register_project(
    store: &mut SqliteDirect,
    lease: &DirectLease,
    admission: &Admission,
    input: &ProjectInit,
    repository: &repository::Repository,
    root: NativePath,
    changed: &mut Vec<String>,
) -> Result<ProjectId> {
    let id = ProjectId::from_bytes(
        execute::facts()?
            .message
            .canonical_bytes()?
            .ok_or_else(|| SeError::invalid("project identity", "fresh canonical UUID"))?,
    )?;
    let kernel = Kernel::new(execute::facts()?)?;
    let mut snap = super::super::select::open_snapshot(store, admission)?;
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
            admission,
        },
    );
    snap.close().map_err(|e| store_error(&e))?;
    let committed = append(store, lease, batch?, changed)?;
    let mut snap = super::super::select::open_snapshot(store, admission)?;
    let event = project::committed_registration(
        &committed,
        &mut Cx {
            read: &mut snap,
            admission,
        },
    );
    let project = execute::finish_read(event, snap.close().map_err(|e| store_error(&e)))?;
    if committed.state == se_store::CommitState::Committed {
        changed.push("registered the project".into());
    }
    Ok(project)
}
fn record_git_identity(
    repository: &repository::Repository,
    id: &ProjectId,
    created: bool,
    changed: &mut Vec<String>,
) {
    if let Some(view) = &repository.git
        && let Some(head) = &view.head
    {
        match super::super::git_identity::record(
            &repository.path,
            &id.to_string(),
            head,
            &view.branch,
        ) {
            Ok(path) if created => changed.push(format!(
                "recorded the git identity for future moves in {}",
                path.display()
            )),
            Ok(_) => {}
            Err(e) => {
                let note = match e.body.detail() {
                    se_types::Detail::SourceUnreadable(detail) => detail.reason.clone(),
                    _ => "the marker write failed".into(),
                };
                changed.push(format!(
                    "could not record the git identity for future moves: {note}"
                ))
            }
        }
    }
}
fn import_hint(repository: &repository::Repository) -> Option<String> {
    let node_source = repository.path.join(".stateengine/projects.jsonl");
    if cfg!(feature = "import") {
        match se_proc::NativeSourcePin::open(&node_source) {
            Ok(Some(_)) => {
                Some("Node history detected. Preserve an immutable source copy, then run se import --from-node PATH.".into())
            }
            Ok(None) => None,
            Err(error) => {
                Some(format!("Node history could not be inspected: {error}; preserve its source before importing."))
            }
        }
    } else {
        None
    }
}
fn project_metadata(
    store: &SqliteDirect,
    admission: &Admission,
    id: &ProjectId,
) -> Result<(se_store::ProjectionRecord, String)> {
    let mut snap = super::super::select::open_snapshot(store, admission)?;
    let metadata = scope::require_present(
        snap.project(id.clone()).map_err(|e| store_error(&e))?,
        "initialized project",
        "Read the original project metadata in this data home, then retry se init with its original --key; preserve existing project and machine identities.",
    )?;
    snap.close().map_err(|e| store_error(&e))?;
    let Some((_, project_name, _)) = select::active_project(&metadata.current.body) else {
        return Err(scope::unreadable(
            "initialized project",
            "active project metadata is unavailable",
        ));
    };
    let project_name = project_name.to_owned();
    Ok((metadata, project_name))
}
fn outcome(created: bool, repository: &repository::Repository) -> InitOutcome {
    if created {
        if repository.nonempty || repository.git.is_some() {
            InitOutcome::Adopted
        } else {
            InitOutcome::Created
        }
    } else {
        InitOutcome::AlreadyPresent
    }
}
fn agent_view(
    agent: &AgentRow,
    agent_created: bool,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<InitialAgent> {
    Ok(InitialAgent {
        harness: agent.harness.clone(),
        id: agent.id.clone(),
        name: agent.name.clone(),
        outcome: if agent_created {
            IdentityOutcome::Created
        } else {
            IdentityOutcome::Existing
        },
        provider: agent.provider,
        model: agent.model.clone(),
        permission_profile: project::saved_profile(configuration, agent)?,
    })
}
fn project_view(
    id: &ProjectId,
    name: String,
    repository: &repository::Repository,
    metadata: &se_store::ProjectionRecord,
) -> Result<ProjectView> {
    Ok(ProjectView {
        id: id.clone(),
        name,
        root: repository.path.display().to_string(),
        registered_at: receipt::timestamp(
            metadata
                .original
                .as_deref()
                .unwrap_or(&metadata.current)
                .recorded_at_us,
        )?,
        git: None,
    })
}
