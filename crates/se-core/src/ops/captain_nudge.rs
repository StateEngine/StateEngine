//! Whether the engine should nudge a quiet crew member, decided from stored
//! facts only, so attempts and the stuck alert survive a host restart.
//!
//! A nudge is a task message from the owner through the host door that refers
//! to the agent's open assignments. Attempts are the nudges since the agent's
//! last outward progress: a message it sent, its working note, or a change to
//! one of its assignments. A turn that does none of these is not progress.
use crate::{
    commit::{Cx, MessageKind, MessageSend, OpStep},
    scope,
    store_error::store_error,
};
use se_store::{Actor, Door, EventBody, MailDirection, MessageQuery, ReadBudget, Snapshot};
use se_types::{AgentId, EventId, IdempotencyKey, PageRequest, Read, Result, SeError};
use std::{num::NonZeroU32, time::Duration};

/// The plain words of every nudge; the assignment ids travel as refs.
const NUDGE_TEXT: &str = "You have an open assignment and have been idle. Continue it, or tell your captain why you stopped.";
/// How many of the owner's newest messages to this agent are read for nudges.
const NUDGE_SCAN: u32 = 50;

/// Plan the one message the stored facts call for now, if any: a nudge to the
/// agent about its open assignments, or, once the attempts are spent, one
/// stuck alert to the captain. The commit's continuation names its recipient.
pub fn plan<R: Snapshot>(
    kernel: &crate::dispatch::Kernel,
    agent: &AgentId,
    attempts: u32,
    cx: &mut Cx<'_, R>,
) -> Result<OpStep<Option<AgentId>, (crate::ports::Then, AgentId)>> {
    let terminal = crate::admission::HumanTerminal::Refused {
        reason: "the engine sends this nudge".into(),
    };
    let owner = cx.admission.actor.clone();
    let Some((to, message)) = decide(agent, attempts, &owner, cx)? else {
        return Ok(OpStep::Complete(None));
    };
    match kernel.plan(super::AnyOp::MessageSend(message), cx, &terminal)? {
        OpStep::Commit { batch, then } => Ok(OpStep::Commit {
            batch,
            then: (then, to),
        }),
        _ => Err(scope::unreadable(
            "captain nudge",
            "the nudge message did not plan a commit",
        )),
    }
}

fn decide<R: Snapshot>(
    agent: &AgentId,
    attempts: u32,
    owner: &Actor,
    cx: &mut Cx<'_, R>,
) -> Result<Option<(AgentId, MessageSend)>> {
    let Some(captain) = captain(cx)? else {
        return Ok(None);
    };
    let me = Actor::Agent(agent.clone());
    if captain == me {
        return Ok(None);
    }
    let assignments = open_work(agent, cx)?;
    if assignments.is_empty() || super::agent_state::open_question(agent, cx)?.is_some() {
        return Ok(None);
    }
    let mut progress = newest(cx, None, me.clone(), 1)?
        .first()
        .map(|message| occurred_at(cx, &message.event))
        .transpose()?
        .unwrap_or(i64::MIN);
    // An unreadable note is never taken as no note: that could miscount attempts.
    match cx
        .read
        .working_state(agent.clone())
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => {
            progress = progress.max(super::receipt::event_time(&value.current))
        }
        Read::Absent { .. } => {}
        other => {
            scope::require_present(other, "working note", scope::COMMITTED_READ_RECOVERY)?;
        }
    }
    for (_, latest) in &assignments {
        progress = progress.max(occurred_at(cx, latest)?);
    }
    // A nudge refers only to this agent's open assignments. That keeps other
    // host-door owner mail out of the count, and closing an assignment retires
    // the nudges that named it.
    let open: Vec<_> = assignments.iter().map(|(id, _)| id).collect();
    let mut nudges = Vec::new();
    for message in newest(cx, Some(me), owner.clone(), NUDGE_SCAN)? {
        let event = event(cx, &message.event)?;
        if event.header.occurred_at_us <= progress {
            break;
        }
        if event.header.door == Door::Host
            && message.kind == "task"
            && !message.refs.is_empty()
            && message.refs.iter().all(|id| open.contains(&id))
        {
            nudges.push(message.event);
        }
    }
    let refs = assignments.iter().map(|(id, _)| id.to_string());
    let Some(last) = nudges
        .first()
        .filter(|_| nudges.len() as u64 >= u64::from(attempts))
    else {
        let key = key("nudge", agent, progress, nudges.len())?;
        return Ok(Some((
            agent.clone(),
            MessageSend {
                refs: refs.collect(),
                ..message(agent, NUDGE_TEXT.into(), key)
            },
        )));
    };
    let Actor::Agent(captain) = captain else {
        return Ok(None);
    };
    let alerted = newest(
        cx,
        Some(Actor::Agent(captain.clone())),
        owner.clone(),
        NUDGE_SCAN,
    )?
    .iter()
    .any(|message| message.refs.contains(last));
    if alerted {
        return Ok(None);
    }
    let name = super::receipt::actor_ref(cx.read, &Actor::Agent(agent.clone()))?.name;
    let text = format!(
        "{name} is stuck: it stayed idle on its open assignment after {} nudges with no message, working note or assignment update. Check on it or reassign the work.",
        nudges.len()
    );
    let key = key("stuck", agent, progress, nudges.len())?;
    Ok(Some((
        captain.clone(),
        MessageSend {
            kind: MessageKind::Blocker,
            refs: refs.chain([last.to_string()]).collect(),
            ..message(&captain, text, key)
        },
    )))
}

fn message(to: &AgentId, body: String, idempotency_key: IdempotencyKey) -> MessageSend {
    MessageSend {
        to: Some(to.to_string()),
        body,
        quiet: false,
        kind: MessageKind::Task,
        refs: Vec::new(),
        reply_to: None,
        supersedes: None,
        work: None,
        idempotency_key,
    }
}

/// One key per stall and attempt, so a retried commit never sends twice.
fn key(what: &str, agent: &AgentId, progress: i64, attempt: usize) -> Result<IdempotencyKey> {
    IdempotencyKey::new(format!(
        "captain-{what}-{agent}-{}-{attempt}",
        progress.max(0)
    ))
}

fn captain<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<Option<Actor>> {
    match cx.read.project_captain().map_err(|e| store_error(&e))? {
        Read::Absent { .. } => Ok(None),
        Read::Present { value } => match value.current.body {
            EventBody::ProjectCaptainChanged { captain, .. } => Ok(captain),
            _ => Err(scope::unreadable(
                "captain",
                "designation event has the wrong kind",
            )),
        },
        other => {
            scope::require_present(other, "captain", scope::COMMITTED_READ_RECOVERY)?;
            Err(scope::unreadable(
                "captain read",
                "unexpected present value",
            ))
        }
    }
}

/// This agent's open and working assignments with each one's latest event.
/// Blocked work has already said why it stopped, so it is never nudged.
fn open_work<R: Snapshot>(agent: &AgentId, cx: &mut Cx<'_, R>) -> Result<Vec<(EventId, EventId)>> {
    let mut work = Vec::new();
    let mut cursor = None;
    loop {
        let page =
            super::assignment::list(super::assignment::AssignmentList { limit: 100, cursor }, cx)?;
        cursor = page.page.next().cloned();
        work.extend(
            page.page
                .into_items()
                .into_iter()
                .filter(|row| &row.assignee == agent && row.state != "blocked")
                .map(|row| (row.id, row.latest_event)),
        );
        if cursor.is_none() {
            return Ok(work);
        }
    }
}

fn newest<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    recipient: Option<Actor>,
    sender: Actor,
    limit: u32,
) -> Result<Vec<se_store::MessageRecord>> {
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
            limit: NonZeroU32::new(limit)
                .ok_or_else(|| SeError::invalid("nudge scan", "positive"))?,
            max_bytes: NonZeroU32::new(256 * 1024)
                .ok_or_else(|| SeError::invalid("nudge bytes", "positive"))?,
        },
        deadline: Duration::from_secs(2),
    };
    Ok(cx
        .read
        .messages(query, budget)
        .map_err(|e| store_error(&e))?
        .into_items())
}

fn event<R: Snapshot>(cx: &mut Cx<'_, R>, id: &EventId) -> Result<se_store::StoredEvent> {
    scope::require_present(
        cx.read.event(id.clone()).map_err(|e| store_error(&e))?,
        "nudge event",
        scope::COMMITTED_READ_RECOVERY,
    )
}

fn occurred_at<R: Snapshot>(cx: &mut Cx<'_, R>, id: &EventId) -> Result<i64> {
    Ok(event(cx, id)?.header.occurred_at_us)
}
