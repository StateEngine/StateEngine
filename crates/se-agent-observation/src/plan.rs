//! Only immutable store facts cross the SQL/native boundary.
use super::*;
use se_core::{ops::process_commit, scope, store_error::store_error};
use se_store::{Actor, Consent, EventBody, Snapshot, StoredText};

impl RecordedExit {
    pub fn from_event(event: &EventBody<StoredText>) -> Self {
        match event {
            EventBody::ProcessTransition {
                to: se_store::ProcessState::Exited,
                outcome,
                ..
            } if outcome == process_commit::ENDED_BY_REBOOT => Self::Reboot,
            _ => Self::Other,
        }
    }
}

pub fn prepare_agent_observation<S: Snapshot>(
    project: &ProjectId,
    row: &AgentRow,
    read: &mut S,
) -> Result<AgentObservationPlan> {
    match prepare(project, row, read) {
        Ok(plan) => Ok(plan),
        Err(error) => {
            let mut row = row.clone();
            degrade(&mut row, &error);
            Ok(AgentObservationPlan::new(
                project.clone(),
                row,
                unreadable("agent session preparation", &error),
                RecordedExit::Other,
                unreadable("agent session preparation", &error),
            ))
        }
    }
}
type SessionProcess = (
    Read<se_store::ProcessIdentityRecord>,
    Option<String>,
    RecordedExit,
);

fn resolve_session_process<S: Snapshot>(
    row: &AgentRow,
    session: &se_types::SessionId,
    head: &se_store::ProjectionRecord,
    read: &mut S,
) -> Result<SessionProcess> {
    let process = match &head.current.body {
        EventBody::SessionActivated {
            process: Some(process),
            ..
        } => read.process(process.clone()).map_err(|e| store_error(&e))?,
        _ => match read
            .control_target(row.id.clone())
            .map_err(|e| store_error(&e))?
        {
            Read::Present { value } => value.latest_process,
            other => missing(other),
        },
    };
    let mut control_failure = None;
    let mut recorded_exit = RecordedExit::Other;
    let process = match process {
        Read::Present { value } => {
            let exit = RecordedExit::from_event(&value.current.body);
            let failure = match &value.current.body {
                EventBody::ProcessTransition {
                    to: se_store::ProcessState::StopUnproved | se_store::ProcessState::Lost,
                    outcome,
                    ..
                } => Some(outcome.clone()),
                _ => None,
            };
            let identity = match value.current.body {
                EventBody::ProcessRegistered { identity, .. }
                | EventBody::ProcessTransition { identity, .. } => *identity,
                _ => return Err(invalid("the matching immutable process projection")),
            };
            if identity.session.as_ref() != Some(session) {
                Read::Absent {
                    checked: "the latest recorded process belongs to a different session; it is not substituted for this session".into(),
                }
            } else if identity.principal != Actor::Agent(row.id.clone()) {
                return Err(invalid(
                    "a process projection belonging to this exact agent session",
                ));
            } else {
                control_failure = failure;
                recorded_exit = exit;
                Read::Present { value: identity }
            }
        }
        other => missing(other),
    };
    Ok((process, control_failure, recorded_exit))
}
fn prepare<S: Snapshot>(
    project: &ProjectId,
    row: &AgentRow,
    read: &mut S,
) -> Result<AgentObservationPlan> {
    let Some(session) = row.session.session_id.clone() else {
        return Ok(AgentObservationPlan::new(
            project.clone(),
            row.clone(),
            Read::Absent {
                checked: "this saved agent has never launched a session".into(),
            },
            RecordedExit::Other,
            Read::Absent {
                checked: "no launched conversation to verify".into(),
            },
        ));
    };
    let head = scope::require_present(
        read.session(session.clone()).map_err(|e| store_error(&e))?,
        "agent observation session",
        "Refresh this agent's recorded session before observing it.",
    )?;
    let first = head.original.as_deref().unwrap_or(&head.current);
    if first.header.scope != se_store::Scope::Project(project.clone()) {
        return Err(invalid(
            "the exact selected project for the observed session",
        ));
    }
    let reference = match se_core::ops::session_reference::read(read, &head)? {
        Read::Present { value } => Some(value.as_str().to_owned()),
        Read::Absent { .. } => None,
        other => Some(
            scope::require_present(
                other,
                "observed provider reference",
                "Restore the original provider binding.",
            )?
            .as_str()
            .to_owned(),
        ),
    };
    if !matches!(&first.body, EventBody::SessionPrepared {session:found, agent, ..}
        if found == &session && agent == &row.id && row.conversation.id == reference)
    {
        return Err(invalid("the original session/agent/conversation binding"));
    }
    let (process, control_failure, recorded_exit) =
        resolve_session_process(row, &session, &head, read)?;
    let capture = capture_evidence(
        project,
        &session,
        &row.id,
        row.conversation.id.as_deref(),
        read,
    )
    .unwrap_or_else(|error| unreadable("committed conversation capture", error));
    Ok(AgentObservationPlan {
        control_failure,
        setup_expired: se_core::ops::agent_launch::expired_attended_setup(&head),
        setup_retryable: se_core::ops::agent_launch::retryable_attended_setup(&head),
        ..AgentObservationPlan::new(
            project.clone(),
            row.clone(),
            process,
            recorded_exit,
            capture,
        )
    })
}
fn check_capture_outcome<S: Snapshot>(
    source_id: se_store::RecordId,
    session: &se_types::SessionId,
    read: &mut S,
) -> Result<Option<Read<SourceEvidence>>> {
    // Native exit and session retirement do not erase a failed final capture.
    // Keep its diagnostic until capture advances the cursor or a trusted final
    // reader verifies EOF at that cursor, including a retry with no new records.
    let outcome = read
        .capture_outcome(source_id, None)
        .map_err(|e| store_error(&e))?;
    let failure = match &outcome {
        Read::Present { value } => Some(value),
        Read::Absent { .. } => None,
        _ => return Err(invalid("the latest capture outcome is unavailable")),
    };
    if let Some(failure) = failure {
        match &failure.body {
            EventBody::CaptureVerified {
                source: found,
                session: recorded,
                ..
            } if *found == source_id && recorded == session => (),
            EventBody::CaptureFailed {
                source,
                session: found,
                cause,
                code,
                ..
            } if *source == source_id && found == session => {
                return Ok(Some(unreadable(
                    "transcript capture",
                    format!(
                        "Capture failed since the last committed turn ({code:?}): {cause}. The saved cursor is preserved; retry capture or stop to reconcile."
                    ),
                )));
            }
            _ => return Err(invalid("the exact session/source capture failure")),
        }
    }
    Ok(None)
}
fn verify_turn_evidence<S: Snapshot>(
    session: &se_types::SessionId,
    agent: &se_types::AgentId,
    progress: (&[u8], u64, u64, Option<&SourceEvidence>),
    turn: se_store::StoredEvent,
    read: &mut S,
) -> Result<Read<SourceEvidence>> {
    let (incarnation, from, to, replay) = progress;
    if let Some(evidence) = replay {
        let EventBody::SessionTurn {
            agent: selected_agent,
            provider: backend @ (se_store::Provider::Claude | se_store::Provider::Codex),
            vendor_ref,
            text: StoredText::Present(_),
            ..
        } = &turn.body
        else {
            return Err(invalid("a retained Claude or Codex conversation item"));
        };
        let original = scope::require_present(
            read.native_turn(session.clone(), *backend, vendor_ref)
                .map_err(|e| store_error(&e))?,
            "resumed native item",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if selected_agent == agent
            && original.header.event == turn.header.event
            && evidence.incarnation == incarnation
            && evidence.offset == from
            && evidence.offset.checked_add(evidence.length) == Some(to)
            && evidence.sha256.is_some()
        {
            return Ok(Read::Present {
                value: evidence.clone(),
            });
        }
        return Err(invalid(
            "the current native conversation and verified replay range",
        ));
    }
    match turn.body {
        EventBody::SessionTurn {
            session: found,
            agent: principal,
            evidence,
            text: StoredText::Present(_),
            ..
        } if &found == session
            && &principal == agent
            && evidence.incarnation == incarnation
            && evidence.offset == from
            && evidence.offset.checked_add(evidence.length) == Some(to)
            && evidence.sha256.is_some() =>
        {
            Ok(Read::Present { value: evidence })
        }
        _ => Err(invalid(
            "the current capture cursor and its exact original source evidence",
        )),
    }
}
fn capture_evidence<S: Snapshot>(
    project: &ProjectId,
    session: &se_types::SessionId,
    agent: &se_types::AgentId,
    conversation: Option<&str>,
    read: &mut S,
) -> Result<Read<SourceEvidence>> {
    let source_id = process_commit::session_credential_id(session, "capture-source")?;
    let source = match read
        .capture_source(source_id)
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => value,
        other => return Ok(missing(other)),
    };
    let first = source.original.as_deref().unwrap_or(&source.current);
    if first.header.scope != se_store::Scope::Project(project.clone()) {
        return Err(invalid(
            "the selected project for the committed capture source",
        ));
    }
    if !matches!(&first.body,EventBody::CaptureSource {session:found,consent:Consent::Capture,native_ref,..}
        if found==session && conversation==Some(native_ref.as_str()))
    {
        return Ok(Read::Unknown {
            what: "No capture consent and source are bound to this session".into(),
        });
    }
    if let Some(failed) = check_capture_outcome(source_id, session, read)? {
        return Ok(failed);
    }
    let (incarnation, from, to, turn, replay) = match &source.current.body {
        EventBody::CaptureProgress {
            incarnation,
            old_offset,
            new_offset,
            last_turn,
            replay_evidence,
            ..
        } => (
            incarnation,
            *old_offset,
            *new_offset,
            *last_turn,
            replay_evidence.as_ref(),
        ),
        _ => {
            return Ok(Read::Unknown {
                what: "No committed captured turn has established a conversation cursor yet".into(),
            });
        }
    };
    let turn = match read.turn(turn).map_err(|e| store_error(&e))? {
        Read::Present { value } => value,
        other => return Ok(missing(other)),
    };
    verify_turn_evidence(session, agent, (incarnation, from, to, replay), turn, read)
}

/// Copy the same trusted file evidence used by status before a native reopen.
/// Historical imports and event-only capture do not assert a local file path.
pub fn resume_source<S: Snapshot>(
    plan: &se_core::ops::agent_launch::LaunchPlan,
    read: &mut S,
) -> Result<Option<se_types::NativePath>> {
    let Read::Present { value: latest } = &plan.control.resume_session else {
        return Ok(None);
    };
    let first = latest.original.as_deref().unwrap_or(&latest.current);
    if first.header.door == se_store::Door::Import {
        return Ok(None);
    }
    let EventBody::SessionPrepared { session, .. } = &first.body else {
        return Err(invalid("the original saved session preparation"));
    };
    let conversation = match &plan.conversation {
        Read::Present { value } => Some(value.as_str()),
        _ => return Ok(None),
    };
    match capture_evidence(
        &plan.project.id,
        session,
        &plan.agent.id,
        conversation,
        read,
    )? {
        Read::Present { value } => Ok(value.path),
        _ => Ok(None),
    }
}
