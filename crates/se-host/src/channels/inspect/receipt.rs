//! Saved, notice, read, reply and provider-send facts stay independent.
use super::*;
use se_store::{Actor, EventBody, Role, SqliteSnapshot, channel::SavedUpdate};
pub(super) fn receipt(
    read: &mut SqliteSnapshot,
    state: &Connection,
    saved: SavedUpdate,
    at: i64,
) -> Result<ChannelReceipt> {
    let message = se_core::scope::require_present(
        read.message(saved.message.clone())
            .map_err(|e| store_error(&e))?,
        "saved channel mail",
        "Restore access to the original saved mail.",
    )?;
    let notice = match message.delivered.as_ref() {
        Some(position) => {
            let delivered = se_core::scope::require_present(
                read.event_position(position).map_err(|e| store_error(&e))?,
                "mail notice fact",
                "Inspect the committed delivery evidence.",
            )?;
            if let EventBody::MessageDelivered {
                message: id,
                recipient,
                evidence,
            } = delivered.body
            {
                if id != saved.message || recipient != Actor::Agent(state.target.agent.clone()) {
                    return Err(channel_error(ChannelError::InvalidInput));
                }
                let capture = se_core::scope::require_present(
                    read.event(evidence).map_err(|e| store_error(&e))?,
                    "notice capture",
                    "Restore access to the original captured notice.",
                )?;
                match capture.body {
                    EventBody::SessionTurn {
                        session,
                        agent,
                        role: Role::User,
                        ..
                    } if agent == state.target.agent => {
                        let session_record = se_core::scope::require_present(
                            read.session(session.clone()).map_err(|e| store_error(&e))?,
                            "notice conversation",
                            "Inspect the captured notice session.",
                        )?;
                        let original = session_record
                            .original
                            .as_deref()
                            .unwrap_or(&session_record.current);
                        match &original.body {
                            EventBody::SessionPrepared { native_ref, .. } => NoticeFact::Received {
                                event: capture.header.event,
                                session,
                                conversation: native_ref.clone(),
                                at_us: capture.recorded_at_us,
                            },
                            _ => NoticeFact::Unknown {
                                code: "conversation_evidence_unavailable".into(),
                            },
                        }
                    }
                    _ => NoticeFact::Unknown {
                        code: "committed_user_turn_not_proven".into(),
                    },
                }
            } else {
                NoticeFact::Unknown {
                    code: "delivery_evidence_unavailable".into(),
                }
            }
        }
        None => {
            let mut reason = message
                .notifications
                .first()
                .and_then(|n| n.code.clone())
                .unwrap_or_else(|| "pending_notice".into());
            if let Read::Present { value } = read
                .control_target(state.target.agent.clone())
                .map_err(|e| store_error(&e))?
                && value.sessions.is_empty()
            {
                reason = if !value.processes.is_empty() {
                    "native_custody_unresolved".into()
                } else if matches!(value.latest_session, Read::Absent { .. }) {
                    "agent_not_started".into()
                } else {
                    "agent_stopped_waiting_for_authorized_resume".into()
                };
            }
            NoticeFact::Pending { reason }
        }
    };
    let read_fact = message
        .read
        .as_ref()
        .map(|position| {
            let event = se_core::scope::require_present(
                read.event_position(position).map_err(|e| store_error(&e))?,
                "recipient read fact",
                "Inspect the exact recipient's read marker.",
            )?;
            if event.header.actor != Actor::Agent(state.target.agent.clone()) {
                return Err(channel_error(ChannelError::InvalidInput));
            }
            Ok(CommittedFact {
                event: event.header.event,
                at_us: event.recorded_at_us,
            })
        })
        .transpose()?;
    let outputs = read
        .channel_replies(&state.id, &saved.message)
        .map_err(|e| store_error(&e))?;
    let mut replies = Vec::new();
    for output in outputs.items {
        let Some(reply) = output.reply else { continue };
        let row = se_core::scope::require_present(
            read.message(reply.clone()).map_err(|e| store_error(&e))?,
            "channel reply",
            "Inspect its committed linked mail.",
        )?;
        if row.sender != Actor::Agent(state.target.agent.clone())
            || row.reply_to.as_ref() != Some(&saved.message)
        {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        let event = se_core::scope::require_present(
            read.event(row.event).map_err(|e| store_error(&e))?,
            "reply commit",
            "Inspect the committed reply.",
        )?;
        let telegram = output_fact(
            &output.state,
            output.provider_message,
            output.at_us,
            output.failure,
        )?;
        replies.push(ReplyFact {
            message: reply,
            committed: CommittedFact {
                event: event.header.event,
                at_us: event.recorded_at_us,
            },
            telegram,
        });
    }
    let elapsed = at.saturating_sub(saved.at_us).max(0) as u64 / 1_000_000;
    let delay = if elapsed >= 60 && replies.is_empty() {
        Some(if read_fact.is_some() {
            DelayFact::ReadNoReplyYet {
                elapsed_seconds: elapsed,
                reason: "no_linked_mail_reply".into(),
            }
        } else {
            DelayFact::NotReadYet {
                elapsed_seconds: elapsed,
                reason: if message.dismissed.is_some() {
                    "dismissed_without_read".into()
                } else {
                    "recipient_has_not_marked_read".into()
                },
            }
        })
    } else {
        None
    };
    let resume = match read
        .channel_message_action(&state.id, &saved.message)
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => Some(ResumePresentation {
            state: if value.state == "offered" && value.expires_at_us <= at {
                "expired".into()
            } else {
                value.state
            },
            expires_at_us: value.expires_at_us,
            code: value.code,
        }),
        Read::Absent { .. } => None,
        other => {
            se_core::scope::require_present(
                other,
                "phone lifecycle state",
                "Restore native channel access.",
            )?;
            None
        }
    };
    Ok(ChannelReceipt {
        id: saved.receipt,
        connection: state.id.clone(),
        message: saved.message,
        target: state.target.clone(),
        saved: CommittedFact {
            event: saved.event,
            at_us: saved.at_us,
        },
        notice,
        read: read_fact,
        replies,
        replies_omitted: outputs.omitted,
        delay,
        resume,
        observed_at_us: at,
    })
}

pub(super) fn output_fact(
    state: &str,
    provider: Option<i64>,
    at_us: i64,
    failure: Option<se_types::MessagingChannelError>,
) -> Result<TelegramOutput> {
    Ok(match state {
        "queued" => TelegramOutput::Queued,
        "sending" => TelegramOutput::Unknown {
            code: "attempt_awaiting_reconciliation".into(),
        },
        "sent" => TelegramOutput::Sent {
            provider_message: provider.ok_or_else(|| channel_error(ChannelError::InvalidInput))?,
            at_us,
        },
        "unknown" => TelegramOutput::Unknown {
            code: "send_outcome_unknown".into(),
        },
        "failed" => TelegramOutput::Failed {
            code: failure
                .map(|reason| reason.code())
                .unwrap_or("send_failed")
                .into(),
        },
        "revoked" => TelegramOutput::Revoked,
        _ => return Err(channel_error(ChannelError::InvalidInput)),
    })
}
