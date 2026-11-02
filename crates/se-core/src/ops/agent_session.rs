//! Bounded recorded session metadata. Recorded activation is not an OS
//! liveness witness, and a provider reference is not proof of resumability.
use super::{ConversationView, ResumeCommand, SessionView, receipt};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{EventBody, Snapshot};
use se_types::{AgentId, Read, Result};

type Views = (SessionView, ConversationView, ResumeCommand);
pub(super) fn read<R: Snapshot>(agent: &AgentId, cx: &mut Cx<'_, R>) -> Result<Views> {
    let mut session = SessionView {
        state: "unknown".into(),
        session_id: None,
        launch_id: None,
        surface: None,
        process: None,
        since: None,
        observed_at: None,
        containment: None,
        containment_cause: None,
    };
    let latest = cx
        .read
        .latest_session(agent.clone())
        .map_err(|error| store_error(&error))?;
    let latest = match latest {
        Read::Absent { .. } => {
            session.state = "never-launched".into();
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
                    command: Some(format!("se launch {agent} --detach --new")),
                    argv: Some(vec![
                        "se".into(),
                        "launch".into(),
                        agent.to_string(),
                        "--detach".into(),
                        "--new".into(),
                    ]),
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
        provider,
        native_ref,
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
    let (current, reason) = match &latest.current.body {
        EventBody::SessionPrepared { session, .. } => (
            session,
            "The latest session is only prepared; provider readiness and process liveness are unobserved.",
        ),
        EventBody::SessionActivated {
            session: current,
            containment,
            process,
            ..
        } => {
            if process.is_none() && *provider == se_store::Provider::SeCode {
                session.surface = Some("secode".into());
            }
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
                    session.containment_cause = Some(
                        match cause {
                            se_store::ContainmentCause::NoUserManager => "no-user-manager",
                            se_store::ContainmentCause::NoDelegation => "no-delegation",
                            se_store::ContainmentCause::CgroupV2Absent => "cgroup-v2-absent",
                            se_store::ContainmentCause::CgroupUnreadable => "cgroup-unreadable",
                            se_store::ContainmentCause::ScopeCreateFailed => "scope-create-failed",
                        }
                        .into(),
                    );
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
    session.session_id = Some(id.clone());
    session.since = Some(receipt::timestamp(latest.current.recorded_at_us)?);
    Ok((
        session,
        ConversationView {
            id: Some(native_ref.clone()),
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
