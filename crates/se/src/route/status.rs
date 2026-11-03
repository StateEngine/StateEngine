//! Finite store reads and authenticated endpoint observations for public status.
use super::{execute, files::Files};
use crate::bootstrap::Bootstrap;
use se_core::{admission::read_scope, ops::*, scope, store_error::store_error};
use se_store::{Actor, Admission, EventBody, MessageQuery, ReadStore, Scope, Snapshot};
use se_types::{Read, Result};
use std::num::NonZeroU32;

pub fn observe<R: ReadStore>(
    cx: &Bootstrap,
    reader: &R,
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
        Files::open(&cx.home).map_err(|e| store_error(&e))?,
        &cx.home.join("runtime.lock"),
        se_store::LeaseIdentity {
            store: Some(reader.info().map_err(|e| store_error(&e))?.id),
            generation: admission.generation,
            mode: se_store::LeaseMode::DirectClient,
        },
    )
    .map_err(|e| store_error(&e))?;
    if lease.is_some() {
        output.runtime.state = "stopped".into();
    }
    if cx.selections.status_all {
        output.scope = "all".into();
        let mut snapshot = reader
            .snapshot(read_scope(admission))
            .map_err(|e| store_error(&e))?;
        let projects = snapshot
            .projects(super::select::budget(None)?)
            .map_err(|e| store_error(&e));
        let closed = snapshot.close().map_err(|e| store_error(&e));
        let projects = match projects {
            Ok(projects) => {
                closed?;
                projects
            }
            Err(error) => {
                return Err(match closed {
                    Ok(()) => error,
                    Err(close) => error.with_cause(close),
                });
            }
        };
        // Empty registration is a measured fact; no per-project runtime
        // counts need to be guessed to render the post-remove --all answer.
        if projects.items().is_empty() && projects.window().complete() {
            output.projects = Some(se_types::Page::new(
                vec![],
                projects.window().clone(),
                projects.next().cloned(),
            )?);
        }
    }
    if let Scope::Project(project) = &admission.scope {
        let mut snap = reader
            .snapshot(read_scope(admission))
            .map_err(|e| store_error(&e))?;
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
                | EventBody::ProjectUpdated { name, roots, .. } => (name, roots),
                _ => {
                    return Err(scope::unreadable(
                        "project status",
                        "selected project metadata is not active",
                    ));
                }
            };
            output.scope = "project".into();
            output.project = Read::Present {
                value: ProjectView {
                    id: project.clone(),
                    name: name.clone(),
                    root: roots
                        .first()
                        .map(|r| r.path.to_local().map(|p| p.display().to_string()))
                        .transpose()?
                        .unwrap_or_default(),
                    registered_at: receipt::timestamp(
                        record
                            .original
                            .as_deref()
                            .unwrap_or(&record.current)
                            .recorded_at_us,
                    )?,
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
                    read: &mut snap,
                    admission,
                },
            )?);
            match &admission.actor {
                Actor::Human(_) => output.inbox.owner_unread = Some(unread),
                Actor::Agent(agent) => {
                    output.inbox.self_unread = Some(unread);
                    let selected = receipt::named_agent(&mut snap, agent)?;
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
        let closed = snap.close().map_err(|e| store_error(&e));
        result?;
        closed?;
    }
    match execute::endpoint(files) {
        Ok(Read::Present { value: endpoint }) => {
            let owner = scope::require_present(
                reader.runtime_owner().map_err(|e| store_error(&e))?,
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
            let verified = se_host::client::BlockingIpcClient::connect_authenticated(
                &endpoint,
                execute::credential(cx, files)?,
                NonZeroU32::new(se_host::client::wire::DEFAULT_REPLY_BYTES)
                    .ok_or_else(|| se_types::SeError::invalid("status reply bound", "positive"))?,
                &options,
            );
            match verified {
                Ok(connection) => {
                    output.runtime.state = "running".into();
                    output.runtime.host = Some(
                        match endpoint.kind {
                            se_host::HostKind::Standalone => "standalone",
                            se_host::HostKind::EmbeddedSecode => "embedded-secode",
                        }
                        .into(),
                    );
                    output.runtime.generation = Some(connection.negotiated().generation.get());
                    output.runtime.endpoint = Some(endpoint_name(&endpoint)?);
                    output.runtime.version = Some(endpoint.package_version.clone());
                    output.runtime.observed_at = Some(generated);
                    let observation_bound =
                        se_host::client::lease::Deadline::from_options(&options)?;
                    output.runtime.process =
                        Some(super::process::observe(&endpoint, &observation_bound)?);
                    drop(connection);
                    #[cfg(any(target_os = "linux", windows))]
                    {
                        let bound = se_host::client::lease::Deadline::from_options(&options)?;
                        match crate::runtime::host::read_detachment(&cx.home, &endpoint, &bound) {
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
            detail: format!("{checked}; endpoint absence does not prove process or agent absence"),
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
    if output.removal.is_none() {
        output.next = NextStep {
            text: "Inspect the selected agent's saved state.".into(),
            command: "se agent show main".into(),
            argv: vec!["se".into(), "agent".into(), "show".into(), "main".into()],
        };
    }
    Ok(output.into())
}
pub fn endpoint_name(endpoint: &se_host::EndpointRecord) -> Result<String> {
    Ok(match &endpoint.address {
        se_host::IpcEndpoint::UnixSocket(path) => path.to_local()?.display().to_string(),
        se_host::IpcEndpoint::WindowsPipe(name) => name.clone(),
    })
}
