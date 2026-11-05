//! Only immutable store facts cross the SQL/native boundary.
use super::*;
use se_core::{ops::process_commit, scope, store_error::store_error};
use se_store::{Actor, Consent, EventBody, Snapshot, StoredText};

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
            Ok(AgentObservationPlan {
                project: project.clone(),
                command_home: None,
                identity: row
                    .session
                    .session_id
                    .clone()
                    .map(|session| crate::SessionIdentity {
                        project: project.clone(),
                        agent: row.id.clone(),
                        session,
                    }),
                row,
                process: unreadable("agent session preparation", &error),
                capture: unreadable("agent session preparation", &error),
                control_failure: None,
            })
        }
    }
}
fn prepare<S: Snapshot>(
    project: &ProjectId,
    row: &AgentRow,
    read: &mut S,
) -> Result<AgentObservationPlan> {
    let Some(session) = row.session.session_id.clone() else {
        return Ok(AgentObservationPlan {
            project: project.clone(),
            command_home: None,
            identity: None,
            row: row.clone(),
            process: Read::Absent {
                checked: "this saved agent has never launched a session".into(),
            },
            capture: Read::Absent {
                checked: "no launched conversation to verify".into(),
            },
            control_failure: None,
        });
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
    let process = match process {
        Read::Present { value } => {
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
            if identity.session.as_ref() != Some(&session) {
                Read::Absent {
                    checked: "the latest recorded process belongs to a different session; it is not substituted for this session".into(),
                }
            } else if identity.principal != Actor::Agent(row.id.clone()) {
                return Err(invalid(
                    "a process projection belonging to this exact agent session",
                ));
            } else {
                control_failure = failure;
                Read::Present { value: identity }
            }
        }
        other => missing(other),
    };
    let capture = capture_evidence(project, &session, row, read)
        .unwrap_or_else(|error| unreadable("committed conversation capture", error));
    Ok(AgentObservationPlan {
        project: project.clone(),
        command_home: None,
        identity: Some(crate::SessionIdentity {
            project: project.clone(),
            agent: row.id.clone(),
            session,
        }),
        row: row.clone(),
        process,
        capture,
        control_failure,
    })
}
fn capture_evidence<S: Snapshot>(
    project: &ProjectId,
    session: &se_types::SessionId,
    row: &AgentRow,
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
        if found==session && row.conversation.id.as_ref()==Some(native_ref))
    {
        return Ok(Read::Unknown {
            what: "No capture consent and source are bound to this session".into(),
        });
    }
    // A terminal session was published only after final capture succeeded.
    // While active, preserve errors newer than the last committed progress.
    if row.session.recorded_state.as_deref() == Some("activated") {
        let failures = read
            .history(
                se_store::HistoryQuery {
                    agent: None,
                    session: Some(session.clone()),
                    kinds: vec![se_store::EventKind::CaptureFailed],
                    families: Vec::new(),
                    transcript: se_store::TranscriptFilter::All,
                    since: Some(source.current.position.clone()),
                },
                se_store::ReadBudget {
                    page: se_types::PageRequest {
                        after: None,
                        limit: std::num::NonZeroU32::new(1)
                            .ok_or_else(|| invalid("positive diagnostic limit"))?,
                        max_bytes: std::num::NonZeroU32::new(32 * 1024)
                            .ok_or_else(|| invalid("positive diagnostic byte bound"))?,
                    },
                    deadline: std::time::Duration::from_secs(1),
                },
            )
            .map_err(|e| store_error(&e))?;
        if let Some(failure) = failures.items().first() {
            return match &failure.body {
                EventBody::CaptureFailed {
                    source,
                    session: found,
                    cause,
                    code,
                    ..
                } if *source == source_id && found == session => Ok(unreadable(
                    "live transcript capture",
                    format!(
                        "Capture failed since the last committed turn ({code:?}): {cause}. The saved cursor is preserved; retry capture or stop to reconcile."
                    ),
                )),
                _ => Err(invalid("the exact session/source capture failure")),
            };
        }
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
            replay_evidence,
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
    if let Some(evidence) = replay {
        let EventBody::SessionTurn {
            agent,
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
        if *agent == row.id
            && original.header.event == turn.header.event
            && &evidence.incarnation == incarnation
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
            && principal == row.id
            && &evidence.incarnation == incarnation
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
