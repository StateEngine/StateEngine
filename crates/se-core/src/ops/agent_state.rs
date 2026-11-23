//! Each agent's state in status, derived from facts StateEngine observes: the
//! session's native life, the host's provider turn and the agent's own mail.
//! Never from a label the agent sets.
use super::{AnyOutput, outputs::*};
use crate::{commit::Cx, store_error::store_error};
use se_store::{Actor, MailDirection, MessageQuery, ReadBudget, Snapshot};
use se_types::{AgentId, PageRequest, Read, Result, SeError};
use std::{num::NonZeroU32, time::Duration};

/// The agent's last outgoing message, when it is a direct question that its
/// recipient has not answered with any later message and that was not
/// superseded. Two newest-first reads of one message each.
pub(crate) fn open_question<R: Snapshot>(
    agent: &AgentId,
    cx: &mut Cx<'_, R>,
) -> Result<Option<WaitingOnView>> {
    let me = Actor::Agent(agent.clone());
    let Some(last) = newest_one(cx, None, me.clone())? else {
        return Ok(None);
    };
    // A superseded question, or one its recipient dismissed, is resolved
    // without a reply.
    if last.kind != "question"
        || last.work.is_some()
        || last.superseded_by.is_some()
        || last.dismissed.is_some()
    {
        return Ok(None);
    }
    let answered = newest_one(cx, Some(me), last.recipient.clone())?
        .is_some_and(|reply| reply.sent.sequence() > last.sent.sequence());
    if answered {
        return Ok(None);
    }
    let to = super::receipt::actor_ref(cx.read, &last.recipient)?.name;
    let asked_at_us = match cx.read.event(last.event).map_err(|e| store_error(&e))? {
        Read::Present { value } => value.header.occurred_at_us,
        _ => return Ok(None),
    };
    Ok(Some(WaitingOnView {
        message_id: last.message,
        to,
        asked_at: super::receipt::timestamp(asked_at_us)?,
        asked_at_us,
    }))
}

/// The agent's last outgoing message, when it is a shared work message handing
/// work to named agents for review (admit) or back to them (return), and none
/// of them has sent this agent anything since. One read for the handoff and
/// one per addressee; no network and no pull-request service is consulted.
pub(crate) fn open_review<R: Snapshot>(
    agent: &AgentId,
    cx: &mut Cx<'_, R>,
) -> Result<Option<ReviewWaitView>> {
    let me = Actor::Agent(agent.clone());
    let Some(last) = newest_one(cx, None, me.clone())? else {
        return Ok(None);
    };
    let Some(work) = last.work.as_ref().filter(|work| {
        matches!(
            work.action,
            se_types::WorkAction::Admit | se_types::WorkAction::Return
        )
    }) else {
        return Ok(None);
    };
    if last.superseded_by.is_some() {
        return Ok(None);
    }
    let mut to = Vec::new();
    for addressee in &work.addressees {
        let reviewer = Actor::Agent(addressee.clone());
        let replied = newest_one(cx, Some(me.clone()), reviewer.clone())?
            .is_some_and(|reply| reply.sent.sequence() > last.sent.sequence());
        if replied {
            return Ok(None);
        }
        to.push(super::receipt::actor_ref(cx.read, &reviewer)?.name);
    }
    let handed_at_us = match cx.read.event(last.event).map_err(|e| store_error(&e))? {
        Read::Present { value } => value.header.occurred_at_us,
        _ => return Ok(None),
    };
    Ok(Some(ReviewWaitView {
        message_id: last.message,
        to,
        handed_at: super::receipt::timestamp(handed_at_us)?,
        handed_at_us,
        summary: match &last.body {
            se_store::StoredText::Present(text) => first_line(text).0,
            se_store::StoredText::Erased { .. } => String::new(),
        },
        refs: last.refs.iter().map(ToString::to_string).collect(),
    }))
}

/// The newest message from `sender`, to `recipient` when given.
fn newest_one<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    recipient: Option<Actor>,
    sender: Actor,
) -> Result<Option<se_store::MessageRecord>> {
    let query = MessageQuery {
        recipient,
        sender: Some(sender),
        kind: None,
        unread_only: false,
        full_body: false,
        direction: MailDirection::NewestFirst,
    };
    let budget = ReadBudget {
        page: PageRequest {
            after: None,
            limit: NonZeroU32::MIN,
            max_bytes: NonZeroU32::new(64 * 1024)
                .ok_or_else(|| SeError::invalid("question bytes", "positive"))?,
        },
        deadline: Duration::from_secs(2),
    };
    Ok(cx
        .read
        .messages(query, budget)
        .map_err(|e| store_error(&e))?
        .into_items()
        .into_iter()
        .next())
}

/// Set every row's state from its final, observed facts. Run once after all
/// observations are merged; running it again gives the same result.
pub fn settle(output: &mut AnyOutput, now_us: i64) -> Result<()> {
    let rows: &mut [AgentRow] = match output {
        AnyOutput::ProjectStatus(value) => match &mut value.value.agents {
            Some(page) => page.items_mut(),
            None => return Ok(()),
        },
        AnyOutput::AgentList(value) => value.value.page.items_mut(),
        AnyOutput::AgentShow(value) => match &mut value.value.agent {
            Read::Present { value } => std::slice::from_mut(value),
            _ => return Ok(()),
        },
        _ => return Ok(()),
    };
    for row in rows {
        row.state = Some(derive(row, now_us)?);
    }
    Ok(())
}

fn derive(row: &AgentRow, now_us: i64) -> Result<AgentStateView> {
    let waiting_on = row.state.as_ref().and_then(|s| s.waiting_on.clone());
    let review = row.state.as_ref().and_then(|s| s.review.clone());
    let local = background(row, now_us);
    let activity = match &row.provider_activity {
        Some(Read::Present { value }) => Some(value),
        _ => None,
    };
    let phase = activity.and_then(|a| Some((a.phase_started_at.clone()?, a.phase_seconds?)));
    let (state, elapsed) = match row.session.state.as_str() {
        "stopped" | "never-launched" => ("stopped", None),
        "starting" => ("starting", None),
        "stopping" => ("stopping", None),
        "running" => match activity.map(|a| a.activity.as_str()) {
            Some("awaiting-provider" | "waiting" | "retrying-authentication") => ("working", phase),
            Some("interrupted" | "failed" | "authentication-required") => ("attention", phase),
            _ if waiting_on.is_some() => ("blocked", None),
            // Local work still running outranks waiting on a reviewer.
            Some("turn-completed" | "idle") if local.is_some() => ("background", local),
            _ if review.is_some() => ("review", None),
            // An unreadable observation is not an absent one.
            _ if matches!(row.provider_activity, Some(Read::Unreadable { .. })) => {
                ("turn-unreadable", None)
            }
            Some("turn-completed" | "idle") => ("idle", phase),
            // Alive, but no host observed its turns: not claimed idle.
            _ => ("running", None),
        },
        // Lost, unknown or unverifiable liveness is never reported as stopped.
        _ => ("unreachable", None),
    };
    let (since, elapsed) = match (state, &waiting_on, elapsed) {
        ("blocked", Some(question), _) => {
            let seconds = u64::try_from((now_us - question.asked_at_us).max(0) / 1_000_000).ok();
            (Some(question.asked_at.clone()), seconds)
        }
        (_, _, Some((started, seconds))) => (Some(started), Some(seconds)),
        _ => match (state, &review) {
            ("review", Some(handoff)) => {
                let seconds = (now_us - handoff.handed_at_us).max(0) / 1_000_000;
                (Some(handoff.handed_at.clone()), u64::try_from(seconds).ok())
            }
            _ => (None, None),
        },
    };
    Ok(AgentStateView {
        state: state.into(),
        since,
        elapsed_seconds: elapsed,
        waiting_on,
        review,
    })
}

/// A text's first non-empty line, at most `NOTE_CHARS` characters, and
/// whether anything was left out.
fn first_line(text: &str) -> (String, bool) {
    let first = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    let short: String = first.chars().take(NOTE_CHARS).collect();
    let truncated = short.len() < first.len() || text.trim() != first;
    (short, truncated)
}

/// When the agent's oldest background process started and how long ago, if it
/// has any.
fn background(row: &AgentRow, now_us: i64) -> Option<(String, u64)> {
    let Some(Read::Present { value }) = &row.background else {
        return None;
    };
    let oldest = value.oldest.as_ref().filter(|_| value.processes > 0)?;
    let seconds = (now_us - oldest.started_at_us).max(0) / 1_000_000;
    Some((oldest.started_at.clone(), u64::try_from(seconds).ok()?))
}

/// An agent row's background processes as its owning runtime reported them for
/// this exact session; a failed runtime read is unreadable, not none.
pub fn host_background(
    row: &AgentRow,
    observed: &std::result::Result<Vec<&AgentRow>, &se_types::SeError>,
) -> Option<Read<BackgroundView>> {
    match observed {
        Ok(rows) => rows
            .iter()
            .find(|other| other.id == row.id && other.session.session_id == row.session.session_id)
            .and_then(|other| other.background.clone()),
        Err(error) => row.session.session_id.as_ref().map(|_| Read::Unreadable {
            source: "agent process scope".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.body.clone())),
        }),
    }
}

/// The most of a working note a status row shows.
const NOTE_CHARS: usize = 160;
/// The agent's working note in short form: its first line, at most
/// `NOTE_CHARS` characters. No note and an unreadable one stay distinct.
pub(crate) fn working_note<R: Snapshot>(
    agent: &AgentId,
    cx: &mut Cx<'_, R>,
) -> Result<Read<WorkingNoteView>> {
    let record = match cx
        .read
        .working_state(agent.clone())
        .map_err(|e| store_error(&e))?
        .into_present()
    {
        Ok(value) => value,
        Err(other) => return Ok(other),
    };
    let saved_at = super::receipt::timestamp(super::receipt::event_time(&record.current))?;
    let se_store::EventBody::WorkingStateSet { text, .. } = &record.current.body else {
        return Ok(Read::Unreadable {
            source: "working note".into(),
            reason: "the current working-state event has another kind".into(),
            error: None,
        });
    };
    let se_store::StoredText::Present(text) = text else {
        return Ok(Read::Unreadable {
            source: "working note".into(),
            reason: "its stored content was erased".into(),
            error: None,
        });
    };
    let (short, truncated) = first_line(text);
    Ok(Read::Present {
        value: WorkingNoteView {
            text: short,
            truncated,
            saved_at,
        },
    })
}

/// Peer summaries from a settled owner status of the same project: every agent
/// but the caller, reduced to the fields a peer row holds.
pub fn peer_rows(owner: &AnyOutput, caller: &AgentId) -> Read<Vec<PeerRow>> {
    let AnyOutput::ProjectStatus(status) = owner else {
        return Read::Unreadable {
            source: "peer summaries".into(),
            reason: "the owner read returned another operation family".into(),
            error: None,
        };
    };
    let Some(agents) = &status.value.agents else {
        return Read::Absent {
            checked: "the owner status listed no agents".into(),
        };
    };
    if agents.next().is_some() {
        return Read::Unknown {
            what: "the project has more agents than one status page; peer summaries are not shown partially".into(),
        };
    }
    Read::Present {
        value: agents
            .items()
            .iter()
            .filter(|row| &row.id != caller)
            .map(|row| PeerRow {
                id: row.id.clone(),
                name: row.name.clone(),
                role: row.role.clone(),
                provider: row.provider,
                state: row.state.clone(),
                working_note: row.working_note.clone(),
            })
            .collect(),
    }
}

/// The peer list a CLI read reports for its caller, from the host answer it
/// merged: copied when the host answered status, unreadable when it answered
/// with an error or another operation, unknown when no host answered. The
/// owner gets no peer list.
pub fn host_peers(
    peers: &mut Option<Read<Vec<PeerRow>>>,
    observed: Option<&Result<AnyOutput>>,
    agent_caller: bool,
) {
    if !agent_caller {
        return;
    }
    *peers = Some(match observed {
        Some(Ok(AnyOutput::ProjectStatus(live))) => match &live.value.peers {
            Some(value) => value.clone(),
            None => Read::Unknown {
                what: "the host answered without peer summaries".into(),
            },
        },
        Some(Ok(_)) => Read::Unreadable {
            source: "peer summaries".into(),
            reason: "the host returned a different operation family".into(),
            error: None,
        },
        Some(Err(error)) => Read::Unreadable {
            source: "peer summaries".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.body.clone())),
        },
        None => Read::Unknown {
            what: "Peer summaries come from the running host, which did not answer this read; start it with se up.".into(),
        },
    });
}
