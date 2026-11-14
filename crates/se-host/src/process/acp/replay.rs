//! Resume uses the complete canonical projection, never a recent history window.
use super::*;
use crate::{acp::CapturedMessage, client::lease::Deadline};
use se_core::ops::{agent_launch::LaunchPlan, process_commit};
use se_store::{Admission, EventBody, Snapshot, StoredText};
use se_types::{PageRequest, Read};
use std::num::NonZeroU32;
impl LaunchCoordinator {
    pub(in crate::process) async fn acp_replay(
        &self,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<Option<Vec<CapturedMessage>>> {
        self.acp_replay_inner(plan, admission, deadline).await.map_err(|mut error| {
            error.body = error.body.with_remedy(se_types::Remedy {
                text: "Restore the original complete capture and retry, or start a separate conversation with se launch <agent> --new. No new input was offered.".into(),
                command: Some(se_types::Cmd::Manual),
            });
            error
        })
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    async fn acp_replay_inner(
        &self,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<Option<Vec<CapturedMessage>>> {
        if plan.profile.provider != se_store::Provider::Acp {
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
            return Err(error("ACP replay", "original saved session unavailable"));
        };
        let previous_source =
            process_commit::session_credential_id(previous_session, "capture-source")?;
        let mut after = None;
        let mut messages = Vec::new();
        let mut total = 0usize;
        let mut rows = 0usize;
        let mut cursors = std::collections::BTreeSet::new();
        loop {
            let agent = plan.agent.id.clone();
            let wanted = conversation.clone();
            let saved_session = previous_session.clone();
            let cursor = after.clone();
            let budget = deadline.remaining()?.min(std::time::Duration::from_secs(5));
            let (page, selected) = self
                .store
                .read(admission.clone(), deadline, move |cx| {
                    if cursor.is_none() {
                        let prior=se_core::scope::require_present(cx.read.capture_source(previous_source).map_err(|e|se_core::store_error::store_error(&e))?,"ACP saved capture","Restore its original capture binding or start a new conversation with --new.")?;
                        let original=prior.original.as_deref().unwrap_or(&prior.current);
                        if !matches!(&original.body,EventBody::CaptureSource { consent:se_store::Consent::Capture,native_ref,.. } if native_ref==&wanted) {
                            return Err(error("ACP replay","The previous session did not consent to canonical capture. Start a new conversation with --new; no saved input was offered again."));
                        }
                        match cx.read.capture_outcome(previous_source, None).map_err(|e|se_core::store_error::store_error(&e))? {
                            Read::Present { value } if matches!(&value.body,EventBody::CaptureFailed { .. }) => {
                                return Err(error("ACP replay","The previous protocol capture is incomplete. Preserve its observed partial history and use --new for a separate conversation; interrupted input will not be replayed."));
                            }
                            Read::Present { value } if matches!(&value.body,EventBody::CaptureVerified { source,session,.. } if *source==previous_source && session==&saved_session) => (),
                            Read::Absent { .. } => (),
                            _ => return Err(error("ACP replay","The original capture outcome is unavailable; no input was offered.")),
                        }
                    }
                    let page = cx
                        .read
                        .conversation_turns(
                            agent,
                            se_store::Provider::Acp,
                            &wanted,
                            se_store::ReadBudget {
                                page: PageRequest {
                                    after: cursor,
                                    limit: NonZeroU32::new(128)
                                        .ok_or_else(|| error("ACP replay", "invalid page bound"))?,
                                    max_bytes: NonZeroU32::new(2 * 1024 * 1024)
                                        .ok_or_else(|| error("ACP replay", "invalid byte bound"))?,
                                },
                                deadline: budget,
                            },
                        )
                        .map_err(|e| se_core::store_error::store_error(&e))?;
                    let mut selected = Vec::new();
                    for event in page.items() {
                        let EventBody::SessionTurn {
                            session,
                            provider: se_store::Provider::Acp,
                            role,
                            text,
                            ..
                        } = &event.body
                        else {
                            continue;
                        };
                        if !matches!(role, se_store::Role::User | se_store::Role::Assistant) {
                            continue;
                        }
                        let source = se_core::scope::require_present(
                            cx.read
                                .capture_source(process_commit::session_credential_id(
                                    session,
                                    "capture-source",
                                )?)
                                .map_err(|e| se_core::store_error::store_error(&e))?,
                            "ACP replay source",
                            "Restore its original capture binding.",
                        )?;
                        let original = source.original.as_deref().unwrap_or(&source.current);
                        let EventBody::CaptureSource { native_ref, .. } = &original.body else {
                            return Err(error("ACP replay", "original source is unavailable"));
                        };
                        if native_ref != &wanted {
                            continue;
                        }
                        let StoredText::Present(text) = text else {
                            return Err(error(
                                "ACP replay",
                                "committed text is erased or unavailable; no input offered",
                            ));
                        };
                        selected.push(CapturedMessage {
                            role: if *role == se_store::Role::User {
                                "user"
                            } else {
                                "assistant"
                            }
                            .into(),
                            text: text.clone(),
                        });
                    }
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
                        error(
                            "ACP replay",
                            "eight-MiB complete-history bound reached; no suffix accepted",
                        )
                    })?;
                messages.push(message);
            }
            if rows > 10000 {
                return Err(error(
                    "ACP replay",
                    "ten-thousand-row read bound reached; no input offered",
                ));
            }
            let Some(next) = page.next().cloned() else {
                if !page.window().complete() {
                    return Err(error(
                        "ACP replay",
                        "history ended without a complete window",
                    ));
                }
                return Ok(Some(messages));
            };
            let encoded =
                serde_json::to_string(&next).map_err(|e| error("ACP replay cursor", e))?;
            if !cursors.insert(encoded) {
                return Err(error("ACP replay", "cursor repeated before completion"));
            }
            after = Some(next);
        }
    }
}
