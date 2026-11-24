//! Resume uses the complete canonical projection, never a recent history window.
use super::*;
use crate::{acp::CapturedMessage, client::lease::Deadline};
use se_core::ops::{agent_launch::LaunchPlan, process_commit};
use se_core::scope::require_present;
use se_store::{
    Admission, Consent, EventBody, ProjectionRecord, Provider, Role, Snapshot, StoredEvent,
    StoredText,
};
use se_types::{PageRequest, Read};
use std::num::NonZeroU32;
fn replay_err(message: &str) -> se_types::SeError {
    error("ACP replay", message)
}
fn orig(record: &ProjectionRecord) -> &StoredEvent {
    record.original.as_deref().unwrap_or(&record.current)
}
fn verify_prior_capture(
    read: &mut impl Snapshot,
    previous_source: se_store::RecordId,
    wanted: &str,
    saved_session: &se_types::SessionId,
) -> Result<()> {
    let prior = require_present(
        read.capture_source(previous_source).map_err(store_error)?,
        "ACP saved capture",
        "Restore its original capture binding or start a new conversation without --resume.",
    )?;
    if !matches!(&orig(&prior).body, EventBody::CaptureSource { consent: Consent::Capture, native_ref, .. } if native_ref == wanted)
    {
        return Err(replay_err(
            "The previous session did not consent to canonical capture. Start a new conversation without --resume; no saved input was offered again.",
        ));
    }
    match read
        .capture_outcome(previous_source, None)
        .map_err(store_error)?
    {
        Read::Present { value } if matches!(&value.body, EventBody::CaptureFailed { .. }) => {
            Err(replay_err(
                "The previous protocol capture is incomplete. Preserve its observed partial history and omit --resume for a separate conversation; interrupted input will not be replayed.",
            ))
        }
        Read::Present { value } if matches!(&value.body, EventBody::CaptureVerified { source, session, .. } if *source == previous_source && session == saved_session) => {
            Ok(())
        }
        Read::Absent { .. } => Ok(()),
        _ => Err(replay_err(
            "The original capture outcome is unavailable; no input was offered.",
        )),
    }
}
fn collect_page_turns(
    read: &mut impl Snapshot,
    items: &[StoredEvent],
    provider: Provider,
    wanted: &str,
) -> Result<Vec<CapturedMessage>> {
    let mut selected = Vec::new();
    for event in items {
        let EventBody::SessionTurn {
            session,
            provider: found,
            role,
            text,
            ..
        } = &event.body
        else {
            continue;
        };
        if *found != provider || !matches!(role, Role::User | Role::Assistant) {
            continue;
        }
        let id = process_commit::session_credential_id(session, "capture-source")?;
        let source = require_present(
            read.capture_source(id).map_err(store_error)?,
            "ACP replay source",
            "Restore its original capture binding.",
        )?;
        let EventBody::CaptureSource { native_ref, .. } = &orig(&source).body else {
            return Err(replay_err("original source is unavailable"));
        };
        if native_ref != wanted {
            continue;
        }
        let StoredText::Present(text) = text else {
            return Err(replay_err(
                "committed text is erased or unavailable; no input offered",
            ));
        };
        let role = if *role == Role::User {
            "user"
        } else {
            "assistant"
        }
        .into();
        selected.push(CapturedMessage {
            role,
            text: text.clone(),
        });
    }
    Ok(selected)
}

impl LaunchCoordinator {
    pub(in crate::process) async fn canonical_replay(
        &self,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<Option<Vec<CapturedMessage>>> {
        self.canonical_replay_inner(plan, admission, deadline).await.map_err(|mut error| {
            error.body = error.body.with_remedy(se_types::Remedy {
                text: "Restore the original complete capture and retry, or start a separate conversation with se launch <agent>. No new input was offered.".into(),
                command: Some(se_types::Cmd::Manual),
            });
            error
        })
    }
    async fn canonical_replay_inner(
        &self,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<Option<Vec<CapturedMessage>>> {
        if !self.harness_for(plan.profile.provider)?.canonical_resume() {
            return Ok(None);
        }
        let conversation = match &plan.conversation {
            Read::Present { value } => value.as_str().to_owned(),
            Read::Absent { .. } => return Ok(None),
            Read::Unreadable { reason, .. } => return Err(error("ACP resume", reason)),
            Read::Unknown { what } => return Err(error("ACP resume", what)),
        };
        let previous = se_core::scope::require_present(
            plan.control.resume_session.clone(),
            "ACP saved session",
            "Restore its original session before loading it.",
        )?;
        let original = previous.original.as_deref().unwrap_or(&previous.current);
        let EventBody::SessionPrepared {
            session: previous_session,
            ..
        } = &original.body
        else {
            return Err(replay_err("original saved session unavailable"));
        };
        let previous_source =
            process_commit::session_credential_id(previous_session, "capture-source")?;
        let provider = plan.profile.provider;
        let (mut after, mut messages, mut total, mut rows) = (None, Vec::new(), 0usize, 0usize);
        let mut cursors = std::collections::BTreeSet::new();
        loop {
            let (agent, wanted, saved_session, cursor) = (
                plan.agent.id.clone(),
                conversation.clone(),
                previous_session.clone(),
                after.clone(),
            );
            let budget = deadline.remaining()?.min(std::time::Duration::from_secs(5));
            let (page, selected) = self
                .store
                .read(admission.clone(), deadline, move |cx| {
                    if cursor.is_none() {
                        verify_prior_capture(cx.read, previous_source, &wanted, &saved_session)?;
                    }
                    let page = cx
                        .read
                        .conversation_turns(
                            agent,
                            provider,
                            &wanted,
                            se_store::ReadBudget {
                                page: PageRequest {
                                    after: cursor,
                                    limit: NonZeroU32::new(128)
                                        .ok_or_else(|| replay_err("invalid page bound"))?,
                                    max_bytes: NonZeroU32::new(2 * 1024 * 1024)
                                        .ok_or_else(|| replay_err("invalid byte bound"))?,
                                },
                                deadline: budget,
                            },
                        )
                        .map_err(store_error)?;
                    let selected = collect_page_turns(cx.read, page.items(), provider, &wanted)?;
                    Ok((page, selected))
                })
                .await?;
            rows += page.items().len();
            for message in selected {
                total = total
                    .checked_add(
                        message.text.len()
                            + message.role.len()
                            + std::mem::size_of::<CapturedMessage>(),
                    )
                    .filter(|n| *n <= 8 * 1024 * 1024)
                    .ok_or_else(|| {
                        replay_err("eight-MiB complete-history bound reached; no suffix accepted")
                    })?;
                messages.push(message);
            }
            if rows > 10000 {
                return Err(replay_err(
                    "ten-thousand-row read bound reached; no input offered",
                ));
            }
            let Some(next) = page.next().cloned() else {
                if !page.window().complete() {
                    return Err(replay_err("history ended without a complete window"));
                }
                return Ok(Some(messages));
            };
            let encoded =
                serde_json::to_string(&next).map_err(|e| error("ACP replay cursor", e))?;
            if !cursors.insert(encoded) {
                return Err(replay_err("cursor repeated before completion"));
            }
            after = Some(next);
        }
    }
}
