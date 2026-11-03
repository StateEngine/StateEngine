//! Only immutable store facts cross the SQL/native boundary.
use super::*;
use se_core::{ops::process_commit, scope, store_error::store_error};
use se_store::{Actor, Consent, EventBody, Snapshot, StoredText};

pub fn prepare_agent_observation<S: Snapshot>(
    project: &ProjectId,
    row: &AgentRow,
    read: &mut S,
) -> Result<AgentObservationPlan> {
    let Some(session) = row.session.session_id.clone() else {
        return Ok(AgentObservationPlan {
            identity: None,
            row: row.clone(),
            process: Read::Absent {
                checked: "this saved agent has never launched a session".into(),
            },
            capture: Read::Absent {
                checked: "no launched conversation to verify".into(),
            },
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
    if !matches!(&first.body, EventBody::SessionPrepared {session:found, agent, native_ref, ..}
        if found == &session && agent == &row.id && row.conversation.id.as_ref() == Some(native_ref))
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
            other => other.map(|_| unreachable!("present handled above")),
        },
    };
    let process = match process {
        Read::Present { value } => {
            let identity = match value.current.body {
                EventBody::ProcessRegistered { identity, .. }
                | EventBody::ProcessTransition { identity, .. } => *identity,
                _ => return Err(invalid("the matching immutable process projection")),
            };
            if identity.session.as_ref() != Some(&session)
                || identity.principal != Actor::Agent(row.id.clone())
            {
                return Err(invalid(
                    "a process projection belonging to this exact agent session",
                ));
            }
            Read::Present { value: identity }
        }
        other => other.map(|_| unreachable!("present handled above")),
    };
    let capture = capture_evidence(project, &session, row, read)?;
    Ok(AgentObservationPlan {
        identity: Some(crate::SessionIdentity {
            project: project.clone(),
            agent: row.id.clone(),
            session,
        }),
        row: row.clone(),
        process,
        capture,
    })
}
fn capture_evidence<S: Snapshot>(
    project: &ProjectId,
    session: &se_types::SessionId,
    row: &AgentRow,
    read: &mut S,
) -> Result<Read<SourceEvidence>> {
    let source = process_commit::session_credential_id(session, "capture-source")?;
    let source = match read.capture_source(source).map_err(|e| store_error(&e))? {
        Read::Present { value } => value,
        other => return Ok(other.map(|_| unreachable!("present handled above"))),
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
    let (incarnation, from, to, turn) = match &source.current.body {
        EventBody::CaptureProgress {
            incarnation,
            old_offset,
            new_offset,
            last_turn,
            ..
        } => (incarnation, *old_offset, *new_offset, *last_turn),
        _ => {
            return Ok(Read::Unknown {
                what: "No committed captured turn has established a conversation cursor yet".into(),
            });
        }
    };
    let turn = match read.turn(turn).map_err(|e| store_error(&e))? {
        Read::Present { value } => value,
        other => return Ok(other.map(|_| unreachable!("present handled above"))),
    };
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
