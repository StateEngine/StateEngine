//! Finite, target-bound lifecycle readback. This never fabricates an OS
//! observation from an activation event or a recorded PID.
use super::*;
use se_store::{
    Actor, ProcessState, ProjectionRecord, RecordedIdentity, RootIdentityState, StoredText,
};
use se_types::SessionId;

pub(super) fn apply<R: Snapshot>(
    agent: &AgentId,
    id: &SessionId,
    head: &EventBody<StoredText>,
    session: &mut SessionView,
    cx: &mut Cx<'_, R>,
) -> Result<()> {
    let (recorded, process) = match head {
        EventBody::SessionPrepared { .. } => ("prepared", None),
        EventBody::SessionActivated { process, .. } => ("activated", process.clone()),
        EventBody::SessionEnded { .. } => ("ended", None),
        EventBody::SessionRevoked { .. } => ("revoked", None),
        _ => {
            return Err(scope::unreadable(
                "session projection",
                "unexpected session head",
            ));
        }
    };
    session.recorded_state = Some(recorded.into());
    if recorded == "prepared" {
        session.state = "starting".into();
    }
    let expected = process.clone();
    let process = match process {
        Some(process) => cx
            .read
            .process(process)
            .map_err(|error| store_error(&error))?,
        None => match cx
            .read
            .control_target(agent.clone())
            .map_err(|error| store_error(&error))?
        {
            Read::Present { value } => value.latest_process,
            other => {
                session.process_state = other.map(|_| String::new());
                return Ok(());
            }
        },
    };
    session.process_state = match process {
        Read::Present { value } => projection(agent, id, expected.as_ref(), value, session)?,
        other => other.map(|_| String::new()),
    };
    Ok(())
}
fn projection(
    agent: &AgentId,
    id: &SessionId,
    expected: Option<&se_types::LifecycleId>,
    record: ProjectionRecord,
    session: &mut SessionView,
) -> Result<Read<String>> {
    let (identity, state) = match &record.current.body {
        EventBody::ProcessRegistered { identity, initial } => (identity, *initial),
        EventBody::ProcessTransition {
            identity,
            to,
            process,
            ..
        } if process == &identity.record => (identity, *to),
        _ => {
            return Err(scope::unreadable(
                "session process projection",
                "current process head is not its registered lifecycle",
            ));
        }
    };
    if expected.is_some_and(|expected| expected != &identity.record) {
        return Err(scope::unreadable(
            "session process projection",
            "the lifecycle differs from the activated session's exact process reference",
        ));
    }
    if identity.principal != Actor::Agent(agent.clone()) {
        return Err(scope::unreadable(
            "session process projection",
            "the process principal differs from the selected agent",
        ));
    }
    if identity.session.as_ref() != Some(id) {
        return Ok(Read::Absent { checked: "The latest recorded process belongs to a different session; it was not substituted for this one".into() });
    }
    if let Some(bytes) = identity.record.canonical_bytes()? {
        session.launch_id = Some(se_types::LaunchId::from_bytes(bytes)?);
    }
    let name = match state {
        ProcessState::Reserved => "reserved",
        ProcessState::Starting => "starting",
        ProcessState::Running => "running",
        ProcessState::LeaderExited => "leader-exited",
        ProcessState::StopRequested => "stop-requested",
        ProcessState::StopUnproved => "stop-unproved",
        ProcessState::Exited => "exited",
        ProcessState::Lost => "lost",
        ProcessState::Historical => "historical",
    };
    session.state = match state {
        ProcessState::Reserved | ProcessState::Starting => "starting",
        ProcessState::StopRequested => "stopping",
        // An immutable witnessed exit belongs to the exact old instance;
        // later reuse of its numeric PID cannot bring that instance back.
        ProcessState::Exited => "stopped",
        ProcessState::Lost => "lost",
        _ => "unknown",
    }
    .into();
    session.liveness = match &identity.instance {
        RecordedIdentity::Unreadable { cause } => Read::Unreadable {
            source: "recorded session process identity".into(),
            reason: cause.clone(),
            error: None,
        },
        RecordedIdentity::Absent { reason }
            if identity.root_identity == RootIdentityState::NoChildCreated =>
        {
            Read::Absent {
                checked: reason.clone(),
            }
        }
        RecordedIdentity::Absent { reason } => Read::Unknown {
            what: format!("The lifecycle has no published root identity: {reason}"),
        },
        RecordedIdentity::Present(_) => Read::Unknown {
            what: format!(
                "The exact process instance is recorded as {name}; a fresh outside observation has not run"
            ),
        },
    };
    Ok(Read::Present { value: name.into() })
}
