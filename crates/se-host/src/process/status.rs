//! Host/MCP status uses the same recorded rows and outside observations as the
//! direct CLI. The host's own identity is witnessed after the finite SQL read.
use super::*;
use crate::{BlockingClass, client::lease::Deadline};
use se_core::{commit::Cx, ops::*, scope, store_error::store_error};
use se_store::{Actor, Admission, EventBody, MessageQuery, Snapshot};
use se_types::{Read, Result};

impl LaunchCoordinator {
    pub(super) async fn status(
        &self,
        input: ProjectStatus,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<AnyOutput> {
        if input.all {
            return Err(error("host status", "use the owner CLI for status --all"));
        }
        let home = self.options.home.display().to_string();
        let (mut output, plans) = self
            .store
            .read(admission, deadline, move |cx| {
                let generated = receipt::timestamp(crate::runtime::start::now_unix_micros()?)?;
                let mut status =
                    se_core::ops::status::missing(home, generated, "no project selected".into());
                status.setup.state = SetupState::Configured;
                status.setup.reason = None;
                project(&mut status, cx)?;
                let output = AnyOutput::from(status);
                let plans = crate::agent_observation::output::prepare(
                    &cx.admission.scope,
                    &output,
                    cx.read,
                )?;
                Ok((output, plans))
            })
            .await?;
        let owner = self.owner.clone();
        let kind = self.kind;
        let generation = self.store.generation.get();
        let bound = deadline.clone();
        let command_home = self.options.home.clone();
        self.store
            .pool
            .run(BlockingClass::Foreground, deadline, move || {
                bound.remaining()?;
                crate::agent_observation::output::observe(
                    &mut output,
                    plans,
                    bound.at(),
                    &command_home,
                )?;
                let observed = se_proc::read_process(owner.machine.clone(), owner.pid)
                    .map_err(|cause| error("host process observation", cause))?;
                let se_proc::ProcessRead::Present(observed) = observed else {
                    return Err(error(
                        "host process observation",
                        "the serving host is not present",
                    ));
                };
                if observed.identity != owner
                    || !matches!(
                        observed.state,
                        se_proc::NativeState::Running | se_proc::NativeState::Stopped
                    )
                {
                    return Err(error(
                        "host process observation",
                        "the exact serving process instance must be live",
                    ));
                }
                let AnyOutput::ProjectStatus(status) = &mut output else {
                    return Err(error("host status", "the original status family"));
                };
                status.value.runtime.state = "running".into();
                status.value.runtime.host = Some(
                    match kind {
                        crate::HostKind::Standalone => "standalone",
                        crate::HostKind::EmbeddedSecode => "embedded-secode",
                    }
                    .into(),
                );
                status.value.runtime.process = Some(launch_util::view(&owner, bound.at())?);
                status.value.runtime.generation = Some(generation);
                status.value.runtime.version = Some(env!("CARGO_PKG_VERSION").into());
                status.value.runtime.observed_at = Some(receipt::timestamp(
                    i64::try_from(observed.observed_at_unix_ns / 1000).map_err(|_| {
                        error("host observation clock", "representable Unix microseconds")
                    })?,
                )?);
                bound.remaining()?;
                Ok(output)
            })
            .await
    }
}

fn project<S: Snapshot>(output: &mut StatusOutput, cx: &mut Cx<'_, S>) -> Result<()> {
    let se_store::Scope::Project(project) = &cx.admission.scope else {
        return Ok(());
    };
    let record = scope::require_present(
        cx.read
            .project(project.clone())
            .map_err(|e| store_error(&e))?,
        "selected project",
        "Select an existing project in this data home.",
    )?;
    output.scope = "project".into();
    if let Some(removal) = project_remove::removed_view(&record)? {
        output.project = Read::Absent {
            checked: format!("project {} was removed", removal.project.name),
        };
        output.removal = Some(removal);
        output.capture.state = "off".into();
        output.atlas.state = "absent".into();
        return Ok(());
    }
    let (name, roots) = match &record.current.body {
        EventBody::ProjectRegistered { name, roots, .. }
        | EventBody::ProjectUpdated { name, roots, .. } => (name, roots),
        _ => {
            return Err(error(
                "selected project",
                "active project metadata is unavailable",
            ));
        }
    };
    output.project = Read::Present {
        value: ProjectView {
            id: project.clone(),
            name: name.clone(),
            root: roots
                .first()
                .map(|root| root.path.to_local().map(|path| path.display().to_string()))
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
    let unread = cx
        .read
        .message_count(MessageQuery {
            sender: None,
            recipient: Some(cx.admission.actor.clone()),
            kind: None,
            unread_only: true,
            full_body: false,
        })
        .map_err(|e| store_error(&e))?;
    match &cx.admission.actor {
        Actor::Human(_) => output.inbox.owner_unread = Some(unread),
        Actor::Agent(agent) => {
            output.inbox.self_unread = Some(unread);
            if let Some(session) = &cx.admission.session {
                output.principal = Some(PrincipalView {
                    project: Named {
                        id: project.clone(),
                        name: name.clone(),
                    },
                    agent: receipt::named_agent(cx.read, agent)?,
                    session_id: session.clone(),
                });
            }
        }
    }
    output.agents = Some(
        se_core::ops::listing::agents(
            AgentList {
                limit: 100,
                cursor: None,
            },
            cx,
        )?
        .page,
    );
    output.next = NextStep {
        text: "Read this agent's saved state.".into(),
        command: "se agent show main".into(),
        argv: vec!["se".into(), "agent".into(), "show".into(), "main".into()],
    };
    Ok(())
}
