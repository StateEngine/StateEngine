//! Single atomic `Door::Host` / owner batch committing both the automated
//! completion notice (`MessageSent`) and terminal retirement (`AgentRetired`).
use crate::{commit::Cx, dispatch::Kernel, ops::process_commit, store_error::store_error};
use se_store::{
    Actor, AtomicBatch, EventBody, EventKind, HistoryDirection, HistoryQuery, InputText,
    ReadBudget, RetirementReason, Role, Snapshot, StoredText, TranscriptFilter,
};
use se_types::{AgentId, IdempotencyKey, Named, PageRequest, Result, SeError, SessionId};
use std::{num::NonZeroU32, time::Duration};

const MAX_EXCERPT_BYTES: usize = 1_500;

/// Honest capture outcome reported in the automated completion notice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureOutcome {
    Verified,
    Incomplete,
    Disabled,
}

/// Metadata required to build the single atomic post-`SessionEnded` batch
/// containing both the automated completion notice (`MessageSent`) and
/// terminal retirement (`AgentRetired { Completed }`).
pub struct CompletionNoticeInput {
    pub agent: Named<AgentId>,
    pub owner: se_types::HumanId,
    pub created_by: Option<Actor>,
    pub child_session: SessionId,
    pub provider: Option<se_store::Provider>,
    pub model: Option<String>,
    pub outcome: String,
    pub capture: CaptureOutcome,
}

/// Build one atomic `Door::Host` / owner batch committing both `MessageSent`
/// (automated completion notice) and `AgentRetired { Completed }`, keyed
/// deterministically on `child_session`. Returns `(batch, notify_agent)`.
pub fn completion_notice_batch<R: Snapshot>(
    kernel: &Kernel,
    input: CompletionNoticeInput,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, Option<AgentId>)> {
    let recipient = match input.created_by {
        Some(Actor::Agent(parent)) => {
            if cx
                .read
                .principal_retired(parent.clone())
                .map_err(|error| store_error(&error))?
            {
                Actor::Human(input.owner.clone())
            } else {
                Actor::Agent(parent)
            }
        }
        Some(Actor::Human(human)) => Actor::Human(human),
        _ => Actor::Human(input.owner.clone()),
    };
    let notify_agent = match &recipient {
        Actor::Agent(agent) => Some(agent.clone()),
        _ => None,
    };
    let excerpt = if input.capture == CaptureOutcome::Verified {
        latest_assistant_excerpt(&input.child_session, cx)?
    } else {
        None
    };
    let capture_label = match input.capture {
        CaptureOutcome::Verified => "verified",
        CaptureOutcome::Incomplete => "incomplete",
        CaptureOutcome::Disabled => "not captured (capture disabled)",
    };
    let provider_label = input.provider.map_or("unknown", stored_provider_label);
    let model_label = input.model.as_deref().unwrap_or("default");
    let mut text = format!(
        "[StateEngine automated notice] Temporary agent {} ({}) finished.\nProvider: {} ({})\nOutcome: {}\nCapture: {}\nHistory: se history --agent {}",
        input.agent.name,
        input.agent.id,
        provider_label,
        model_label,
        input.outcome,
        capture_label,
        input.agent.id
    );
    if let Some(excerpt) = excerpt {
        text.push_str("\n\nFinal response excerpt:\n");
        text.push_str(&excerpt);
    }
    let key: IdempotencyKey = format!("ephemeral-complete-{}", input.child_session).parse()?;
    let notice = EventBody::MessageSent {
        message: kernel.facts()?.message.clone(),
        recipient,
        kind: "done".into(),
        body: InputText::Inline(text),
        refs: Vec::new(),
        reply_to: None,
        quiet: false,
    };
    let retire = EventBody::AgentRetired {
        agent: input.agent.id.clone(),
        reason: RetirementReason::Completed,
        final_session: Some(input.child_session.clone()),
    };
    let batch = process_commit::batch(
        kernel,
        "delegate.complete",
        key,
        serde_json::json!({
            "agent": input.agent.id,
            "session": input.child_session,
            "reason": "completed",
        }),
        vec![notice, retire],
        cx,
    )?;
    Ok((batch, notify_agent))
}

fn latest_assistant_excerpt<R: Snapshot>(
    session: &SessionId,
    cx: &mut Cx<'_, R>,
) -> Result<Option<String>> {
    let budget = ReadBudget {
        page: PageRequest {
            after: None,
            limit: NonZeroU32::new(64).ok_or_else(|| SeError::invalid("limit", "positive"))?,
            max_bytes: NonZeroU32::new(256 * 1024)
                .ok_or_else(|| SeError::invalid("bytes", "positive"))?,
        },
        deadline: Duration::from_secs(2),
    };
    let page = cx
        .read
        .history(
            HistoryQuery {
                agent: None,
                kinds: vec![EventKind::SessionTurn],
                families: Vec::new(),
                session: Some(session.clone()),
                transcript: TranscriptFilter::All,
                since: None,
                direction: HistoryDirection::NewestFirst,
            },
            budget,
        )
        .map_err(|error| store_error(&error))?;
    for event in page.into_items() {
        if let EventBody::SessionTurn {
            role: Role::Assistant,
            text: StoredText::Present(text),
            ..
        } = event.body
        {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(Some(clip_utf8(trimmed, MAX_EXCERPT_BYTES)));
            }
        }
    }
    Ok(None)
}

fn clip_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes.saturating_sub(3);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn stored_provider_label(provider: se_store::Provider) -> &'static str {
    match provider {
        se_store::Provider::Claude => "claude",
        se_store::Provider::Codex => "codex",
        se_store::Provider::SeCode => "secode",
        se_store::Provider::Acp => "acp",
    }
}
