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
    let budget = || -> Result<ReadBudget> {
        Ok(ReadBudget {
            page: PageRequest {
                after: None,
                limit: NonZeroU32::MIN,
                max_bytes: NonZeroU32::new(64 * 1024)
                    .ok_or_else(|| SeError::invalid("question bytes", "positive"))?,
            },
            deadline: Duration::from_secs(2),
        })
    };
    let newest = |recipient: Option<Actor>, sender: Actor| MessageQuery {
        recipient,
        sender: Some(sender),
        kind: None,
        unread_only: false,
        full_body: false,
        direction: MailDirection::NewestFirst,
    };
    let me = Actor::Agent(agent.clone());
    let Some(last) = cx
        .read
        .messages(newest(None, me.clone()), budget()?)
        .map_err(|e| store_error(&e))?
        .into_items()
        .into_iter()
        .next()
    else {
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
    let answered = cx
        .read
        .messages(newest(Some(me), last.recipient.clone()), budget()?)
        .map_err(|e| store_error(&e))?
        .into_items()
        .into_iter()
        .next()
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
        _ => (None, None),
    };
    Ok(AgentStateView {
        state: state.into(),
        since,
        elapsed_seconds: elapsed,
        waiting_on,
    })
}
