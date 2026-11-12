//! Finite store reads and protected endpoint/native identity observations for status.
use super::{execute, files::Files};
use crate::bootstrap::Bootstrap;
use se_core::{admission::read_scope, ops::*, scope, store_error::store_error};
use se_store::{
    Actor, Admission, EventBody, MessageQuery, ReadStore, RuntimeOwnerHead, Scope, Snapshot,
};
use se_types::{Read, Result};
#[path = "status/projects.rs"]
mod projects;

pub fn observe<R: ReadStore>(
    cx: &Bootstrap,
    reader: &R,
    files: &Files,
    admission: &Admission,
) -> Result<AnyOutput> {
    let deadline = super::session_observation::deadline()?;
    let owner = Some(reader.runtime_owner().map_err(|e| store_error(&e))?);
    let mut snapshot = reader
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let result = observe_snapshot(cx, &mut snapshot, owner, files, admission).and_then(|output| {
        super::session_observation::prepare(output, &mut snapshot, admission, deadline)
    });
    let closed = snapshot.close().map_err(|e| store_error(&e));
    match result {
        Ok(value) => {
            closed?;
            let output = super::session_observation::finish(value, &cx.home)?;
            finish(cx, reader, output, admission)
        }
        Err(error) => Err(match closed {
            Ok(()) => error,
            Err(close) => error.with_cause(close),
        }),
    }
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn observe_snapshot<S: Snapshot>(
    cx: &Bootstrap,
    snap: &mut S,
    owner: Option<Read<RuntimeOwnerHead>>,
    files: &Files,
    admission: &Admission,
) -> Result<AnyOutput> {
    let generated = receipt::timestamp(execute::now_us()?)?;
    let mut output = status::missing(
        cx.home.display().to_string(),
        generated.clone(),
        "no project selected in this home".into(),
    );
    output.setup.state = SetupState::Configured;
    output.setup.reason = None;
    output.project = Read::Absent {
        checked: "no project selected; use --project or enter a registered repository".into(),
    };
    // The shared native lock is held for the observation. Its acquisition proves
    // that no host currently holds its required exclusive writer lease.
    let lease = super::files::DirectLease::acquire(
        files,
        &cx.home.join("runtime.lock"),
        se_store::LeaseIdentity {
            store: Some(snap.info().id),
            generation: admission.generation,
            mode: se_store::LeaseMode::DirectClient,
        },
    )
    .map_err(|e| store_error(&e))?;
    if lease.is_some() {
        output.runtime.state = "stopped".into();
    }
    if let Scope::Project(project) = &admission.scope {
        let result = (|| {
            let record = scope::require_present(
                snap.project(project.clone()).map_err(|e| store_error(&e))?,
                "selected project",
                "Select an existing project in this data home with --project, or restore its original project metadata.",
            )?;
            if let Some(removal) = project_remove::removed_view(&record)? {
                output.scope = "project".into();
                output.project = Read::Absent {
                    checked: format!(
                        "registry: last registration of {} was removed",
                        removal.project.name
                    ),
                };
                output.capture.state = "off".into();
                output.atlas.state = "absent".into();
                let quoted_root = if cfg!(windows) {
                    format!("'{}'", removal.root.replace('\'', "''"))
                } else {
                    format!("'{}'", removal.root.replace('\'', "'\"'\"'"))
                };
                output.next = NextStep {
                    text: "Re-adopt this folder".into(),
                    command: format!("se init --repo {quoted_root}"),
                    argv: vec![
                        "se".into(),
                        "init".into(),
                        "--repo".into(),
                        removal.root.clone(),
                    ],
                };
                output.removal = Some(removal);
                return Ok(());
            }
            let (name, roots) = match &record.current.body {
                EventBody::ProjectRegistered { name, roots, .. }
                | EventBody::ProjectUpdated { name, roots, .. } => (name, roots.as_slice()),
                EventBody::ProjectMoved { name, to, .. } => (name, std::slice::from_ref(to)),
                _ => {
                    return Err(scope::unreadable(
                        "project status",
                        "selected project metadata is not active",
                    ));
                }
            };
            output.scope = "project".into();
            let root = roots
                .first()
                .map(|r| r.path.to_local().map(|p| p.display().to_string()))
                .transpose()?
                .unwrap_or_default();
            let git = if root.is_empty() {
                None
            } else {
                match super::git_state::observe(std::path::Path::new(&root)) {
                    Ok(observed) => {
                        if let Some(view) = &observed
                            && view.head.is_some()
                            && view.uncommitted.is_none()
                        {
                            output.pending.push(PendingFact {
                                what: "repository state".into(),
                                since: None,
                                detail: "Uncommitted state is unknown: the working-tree scan outgrew its bounded observation; the branch and commit count are still reported.".into(),
                            });
                        }
                        observed
                    }
                    Err(error) => {
                        output.pending.push(PendingFact {
                            what: "repository state".into(),
                            since: None,
                            detail: format!("Git state could not be read: {error}"),
                        });
                        None
                    }
                }
            };
            output.project = Read::Present {
                value: ProjectView {
                    id: project.clone(),
                    name: name.clone(),
                    root,
                    registered_at: receipt::timestamp(
                        record
                            .original
                            .as_deref()
                            .unwrap_or(&record.current)
                            .recorded_at_us,
                    )?,
                    git,
                },
            };
            let query = MessageQuery {
                sender: None,
                recipient: Some(admission.actor.clone()),
                kind: None,
                unread_only: true,
                full_body: false,
            };
            let unread = snap.message_count(query).map_err(|e| store_error(&e))?;
            output.agents = Some(agent_status::page(
                super::select::budget(None)?,
                &mut se_core::commit::Cx {
                    read: snap,
                    admission,
                },
            )?);
            match &admission.actor {
                Actor::Remote(_) => {
                    return Err(se_types::SeError::invalid(
                        "local status",
                        "local human or agent authority",
                    ));
                }
                Actor::Human(_) => output.inbox.owner_unread = Some(unread),
                Actor::Agent(agent) => {
                    output.inbox.self_unread = Some(unread);
                    let selected = receipt::named_agent(snap, agent)?;
                    if let Some(session) = &admission.session {
                        output.principal = Some(PrincipalView {
                            project: Named {
                                id: project.clone(),
                                name: name.clone(),
                            },
                            agent: selected,
                            session_id: session.clone(),
                        });
                    }
                }
            }
            Ok(())
        })();
        result?;
    }
    match execute::endpoint(files) {
        Ok(Read::Present { value: endpoint }) => {
            let owner = scope::require_present(
                owner.ok_or_else(|| {
                    scope::unreadable(
                        "runtime owner",
                        "status has no same-pin ownership observation",
                    )
                })?,
                "recorded runtime owner",
                "Restore access to the recorded runtime owner in this data home; do not treat an unreadable owner as a stopped host.",
            )?;
            if owner.epoch != endpoint.epoch || owner.generation != endpoint.generation {
                return Err(scope::unreadable(
                    "runtime endpoint",
                    "protected endpoint does not match the store's exact current owner generation",
                ));
            }
            if lease.is_some() {
                output.pending.push(PendingFact{what:"stale endpoint".into(),since:None,detail:"The shared native writer lease is held by this observation; the published endpoint is not an active host owner.".into()});
                return Ok(output.into());
            }
            let options = execute::options();
            let observation_bound = se_host::client::lease::Deadline::from_options(&options)?;
            let verified = super::process::observe(&endpoint, &observation_bound);
            match verified {
                Ok(process) => {
                    output.runtime.state = "running".into();
                    output.runtime.host = Some(
                        match endpoint.kind {
                            se_host::HostKind::Standalone => "daemon",
                            se_host::HostKind::EmbeddedSecode => "secode",
                        }
                        .into(),
                    );
                    output.runtime.generation = Some(endpoint.generation.get());
                    output.runtime.endpoint = Some(endpoint_name(&endpoint)?);
                    output.runtime.version = Some(endpoint.package_version.clone());
                    output.runtime.observed_at = Some(generated);
                    output.runtime.process = Some(process);
                    #[cfg(any(target_os = "linux", windows))]
                    {
                        let bound = se_host::client::lease::Deadline::from_options(&options)?;
                        match crate::runtime::host::read_detachment(files, &endpoint, &bound) {
                            Ok(Read::Present { value }) => {
                                output.runtime.detachment = Some(value.detachment)
                            }
                            Ok(Read::Absent { checked }) => output.pending.push(PendingFact {
                                what: "host detachment".into(),
                                since: None,
                                detail: checked,
                            }),
                            Ok(other) => output.pending.push(PendingFact {
                                what: "host detachment".into(),
                                since: None,
                                detail: format!("{other:?}"),
                            }),
                            Err(error) => output.pending.push(PendingFact {
                                what: "host detachment".into(),
                                since: None,
                                detail: error.to_string(),
                            }),
                        }
                    }
                }
                Err(error) => output.pending.push(PendingFact {
                    what: "runtime observation".into(),
                    since: None,
                    detail: error.to_string(),
                }),
            }
        }
        Ok(Read::Absent { checked }) => output.pending.push(PendingFact {
            what: "runtime observation".into(),
            since: None,
            detail: format!("No runtime connection file was found. Running agents have not been checked; use se doctor for this home. Details: {checked}"),
        }),
        Ok(_) => {
            return Err(scope::unreadable(
                "runtime endpoint",
                "native endpoint read did not establish presence or absence",
            ));
        }
        Err(error) => output.pending.push(PendingFact {
            what: "runtime observation".into(),
            since: None,
            detail: error.to_string(),
        }),
    }
    Ok(output.into())
}
pub fn endpoint_name(endpoint: &se_host::EndpointRecord) -> Result<String> {
    Ok(match &endpoint.address {
        se_host::IpcEndpoint::UnixSocket(path) => path.to_local()?.display().to_string(),
        se_host::IpcEndpoint::WindowsPipe(name) => name.clone(),
    })
}

/// Complete cross-project reads after the selected project's read pin closes.
pub(super) fn finish<R: ReadStore>(
    cx: &Bootstrap,
    reader: &R,
    mut output: AnyOutput,
    admission: &Admission,
) -> Result<AnyOutput> {
    let AnyOutput::ProjectStatus(status) = &mut output else {
        return Ok(output);
    };
    let value = &mut status.value;
    se_host::adoption::status::observe(&cx.home, value);
    if value.removal.is_none() && value.runtime.state != "running" {
        value.atlas.state = if cx.config.value.atlas.enabled {
            "unknown"
        } else {
            "disabled"
        }
        .into();
        value.atlas.reason = Some(
            if cx.config.value.atlas.enabled && value.runtime.state == "stopped" {
                "The runtime is stopped; start it with se up to observe the Atlas index."
            } else if cx.config.value.atlas.enabled {
                "Atlas state is unknown because a live runtime could not be verified; inspect the pending runtime observations."
            } else {
                "Atlas is disabled in the selected config.toml."
            }
            .into(),
        );
    }
    if cx.selections.status_all {
        value.scope = "all".into();
        value.atlas = se_core::ops::status::atlas_view(Ok(Read::Absent {
            checked: "Select one project with --project to observe its Atlas index.".into(),
        }));
        value.projects = Some(projects::page(reader, admission)?);
    }
    if value.removal.is_none() {
        if let Some(row) = value.agents.as_ref().and_then(|page| page.items().first()) {
            let command = if row.session.state == "never-launched" {
                AgentCommand::launch_in_home(&row.id, &cx.home, &scope::project(admission)?, false)
            } else {
                None
            };
            if let Some(command) = command {
                value.next = super::command_hint::next(command, "Launch your first agent");
            } else {
                value.next = next_command(
                    cx,
                    "Inspect your saved agent",
                    vec![
                        "--project".into(),
                        scope::project(admission)?.to_string(),
                        "agent".into(),
                        "show".into(),
                        row.id.to_string(),
                    ],
                )?;
            }
        } else {
            value.next = listing(cx)?;
        }
    }
    Ok(output)
}
fn listing(cx: &Bootstrap) -> Result<NextStep> {
    next_command(
        cx,
        "List your registered projects",
        vec!["status".into(), "--all".into()],
    )
}
fn next_command(cx: &Bootstrap, text: &str, tail: Vec<String>) -> Result<NextStep> {
    let home = AgentCommand::home_argument(&cx.home)
        .ok_or_else(|| scope::unreadable("status command", AgentCommand::HOME_UNAVAILABLE))?;
    let mut argv = vec!["se".into(), "--home".into(), home.into()];
    argv.extend(tail);
    let command = AgentCommand::from_argv(argv)
        .ok_or_else(|| scope::unreadable("status command", AgentCommand::HOME_UNAVAILABLE))?;
    Ok(super::command_hint::next(command, text))
}
