//! Bounded recorded session metadata. Recorded activation is not an OS
//! liveness witness, and a provider reference is not proof of resumability.
use super::{ConversationView, ResumeCommand, SessionView, receipt};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{EventBody, Snapshot};
use se_types::{AgentId, Read, Result};
mod recorded;

type Views = (SessionView, ConversationView, ResumeCommand);
pub(super) fn read<R: Snapshot>(agent: &AgentId, cx: &mut Cx<'_, R>) -> Result<Views> {
    Ok(read_inner(agent, cx).unwrap_or_else(|error| {
        let mut session = empty_session();
        session.liveness = Read::Unreadable {
            source: "recorded agent session".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.body.clone())),
        };
        session.process_state = session.liveness.clone();
        (
            session,
            ConversationView {
                id: None,
                state: "unverifiable".into(),
            },
            ResumeCommand {
                ready: false,
                mode: "unavailable".into(),
                reason: Some(error.to_string()),
                command: None,
                argv: None,
            },
        )
    }))
}
fn empty_session() -> SessionView {
    SessionView {
        state: "unknown".into(),
        recorded_state: None,
        process_state: Read::Absent {
            checked: "No session process selected yet".into(),
        },
        liveness: Read::Unknown {
            what: "A recorded session is not a fresh native liveness observation".into(),
        },
        transcript: Default::default(),
        session_id: None,
        launch_id: None,
        surface: None,
        process: None,
        since: None,
        observed_at: None,
        containment: None,
        containment_cause: None,
    }
}
fn read_inner<R: Snapshot>(agent: &AgentId, cx: &mut Cx<'_, R>) -> Result<Views> {
    let mut session = empty_session();
    let latest = cx
        .read
        .latest_session(agent.clone())
        .map_err(|error| store_error(&error))?;
    let latest = match latest {
        Read::Absent { .. } => {
            session.state = "never-launched".into();
            session.liveness = Read::Absent {
                checked: "No recorded session exists for this agent".into(),
            };
            let command = super::AgentCommand::launch(
                agent,
                None,
                match &cx.admission.scope {
                    se_store::Scope::Project(project) => Some(project),
                    _ => None,
                },
                true,
            );
            return Ok((
                session,
                ConversationView {
                    id: None,
                    state: "none".into(),
                },
                ResumeCommand {
                    ready: false,
                    mode: "new".into(),
                    reason: Some(
                        "No provider conversation has been recorded for this agent.".into(),
                    ),
                    command: Some(command.command),
                    argv: Some(command.argv),
                },
            ));
        }
        other => scope::require_present(
            other,
            "latest saved agent session",
            "Restore access to this agent's recorded sessions before deciding whether it can resume.",
        )?,
    };
    let first = latest.original.as_deref().unwrap_or(&latest.current);
    let EventBody::SessionPrepared {
        session: id,
        agent: recorded_agent,
        surface,
        ..
    } = &first.body
    else {
        return Err(scope::unreadable(
            "latest saved agent session",
            "original preparation is missing",
        ));
    };
    if recorded_agent != agent {
        return Err(scope::unreadable(
            "latest saved agent session",
            "the recorded agent differs from the selected agent",
        ));
    }
    session.surface = Some(
        surface
            .map_or("unrecorded", se_store::SessionSurface::as_str)
            .into(),
    );
    let (current, reason) = match &latest.current.body {
        EventBody::SessionPrepared { session, .. } => (
            session,
            "The latest session is only prepared; provider readiness and process liveness are unobserved.",
        ),
        EventBody::SessionActivated {
            session: current,
            containment,
            ..
        } => {
            match containment {
                se_store::ContainmentFact::Contained { kind, .. } => {
                    session.containment = Some(
                        match kind {
                            se_store::ContainmentKind::Cgroup => "cgroup",
                            se_store::ContainmentKind::Job => "job",
                            se_store::ContainmentKind::ProcessGroup => "process-group",
                        }
                        .into(),
                    )
                }
                se_store::ContainmentFact::Uncontained { cause, .. } => {
                    session.containment = Some("uncontained".into());
                    session.containment_cause = Some(super::containment_cause_code(cause).into());
                }
                se_store::ContainmentFact::NotLaunched
                | se_store::ContainmentFact::Unknown { .. } => (),
            }
            (
                current,
                "The session was activated; current native process liveness and provider resumability have not been observed by this read.",
            )
        }
        EventBody::SessionEnded { session, .. } => (
            session,
            "The recorded session ended; process exit and provider resumability have not been observed by this read.",
        ),
        EventBody::SessionRevoked { session, .. } => (
            session,
            "The latest session was revoked; revocation alone does not prove process exit or provider resumability.",
        ),
        _ => {
            return Err(scope::unreadable(
                "latest saved agent session",
                "current head has the wrong event kind",
            ));
        }
    };
    if current != id {
        return Err(scope::unreadable(
            "latest saved agent session",
            "preparation and current head name different sessions",
        ));
    }
    session.transcript = super::transcript::read(agent, Some(id.clone()), cx);
    session.session_id = Some(id.clone());
    session.since = Some(receipt::timestamp(receipt::event_time(&latest.current))?);
    recorded::apply(agent, id, &latest.current.body, &mut session, cx)?;
    let conversation = match super::session_reference::read(cx.read, &latest)? {
        Read::Present { value } => Some(value.as_str().to_owned()),
        Read::Absent { .. } => None,
        other => Some(
            scope::require_present(
                other,
                "saved provider conversation",
                "Restore the original binding before resuming.",
            )?
            .as_str()
            .to_owned(),
        ),
    };
    Ok((
        session,
        ConversationView {
            id: conversation,
            state: "unverifiable".into(),
        },
        ResumeCommand {
            ready: false,
            mode: "resume".into(),
            reason: Some(reason.into()),
            command: None,
            argv: None,
        },
    ))
}
