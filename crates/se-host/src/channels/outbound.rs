//! Durable output attempts. Unknown effects stay unknown and are never retried.
use super::{service::*, *};
use crate::client::lease::Deadline;
use se_core::store_error::store_error;
use se_store::{
    Actor, Admission, EventBody, Scope, Snapshot, StoredText,
    channel::{Change, Connection, Outbound, OutputOutcome, Pairing},
};
use se_types::Result;

impl Channels {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn flush_output(&self, id: ChannelId, deadline: &Deadline) -> Result<()> {
        let gate = self.output_gate(&id)?;
        let _release = tokio::time::timeout(deadline.remaining()?, gate.lock_owned())
            .await
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
        let state = self.connection(id.clone(), deadline).await?;
        let at = now()?;
        let outputs = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read
                    .channel_pending_outputs(&id, at)
                    .map_err(|e| store_error(&e))
            })
            .await?;
        let Some(output) = outputs.items.into_iter().next() else {
            return Ok(());
        };
        if output.state == "sending" {
            // This task owns the gate and has no live HTTP attempt. A crash or
            // cancelled observer cannot establish what the old attempt did.
            return self
                .finish_output(
                    &state,
                    &output,
                    output.attempt,
                    OutputOutcome::Unknown,
                    deadline,
                )
                .await;
        }
        let Pairing::Paired { .. } = state.pairing else {
            return Err(channel_error(ChannelError::BindingRevoked));
        };
        let text = match self.output_text(&state, &output, deadline).await {
            Ok(text) => Ok(text),
            Err(error) => match error.body.detail() {
                se_types::Detail::MessagingChannelRefused(detail)
                    if matches!(
                        detail.reason,
                        ChannelError::ContentErased
                            | ChannelError::InvalidInput
                            | ChannelError::MessageTooLarge
                    ) =>
                {
                    Err(detail.reason)
                }
                _ => return Err(error),
            },
        };
        let transport = self.transport(state.connector)?;
        let descriptor = transport.descriptor();
        let mut buttons = if text.is_ok() {
            self.resume_keyboard(&state, &output, deadline).await?
        } else {
            vec![]
        };
        let chunks = text.and_then(|mut text| {
            if !descriptor.buttons {
                for button in buttons.drain(..) {
                    text.push_str(&format!("\n{}: /confirm {}", button.label, button.data));
                }
            }
            chunks(&text, descriptor.max_text_utf16)
        });
        let token = if chunks.is_ok() {
            Some(self.token(state.credential.clone(), deadline).await?)
        } else {
            None
        };
        let change = Change::OutputStarted {
            connection: state.id.clone(),
            binding_revision: state.revision,
            output: output.output.clone(),
            expected_attempt: output.attempt,
        };
        self.change(
            state.target.project.clone(),
            intent("channel.output.start", None, &change)?,
            change,
            deadline,
        )
        .await?;
        let attempt = output.attempt + 1;
        let result = match (chunks, token) {
            (Ok(chunks), Some(token)) => {
                self.send_parts(
                    &state, &output, attempt, &token, &chunks, &buttons, deadline,
                )
                .await?
            }
            (Err(reason), _) => Err(reason),
            _ => Err(ChannelError::InvalidInput),
        };
        let outcome = match result {
            Ok(provider_message) => OutputOutcome::Sent { provider_message },
            Err(ChannelError::RateLimited {
                retry_after_seconds,
            }) if attempt < 8 => OutputOutcome::Retry {
                after_us: now()?.saturating_add(i64::from(retry_after_seconds) * 1_000_000),
            },
            Err(
                ChannelError::SendOutcomeUnknown
                | ChannelError::ProviderProtocol
                | ChannelError::ProviderUnreachable,
            ) => OutputOutcome::Unknown,
            Err(error) => {
                self.unavailable(state.id.clone(), error.code())?;
                OutputOutcome::Failed { reason: error }
            }
        };
        self.finish_output(&state, &output, attempt, outcome, deadline)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn send_parts(
        &self,
        state: &Connection,
        output: &Outbound,
        attempt: u64,
        token: &se_types::Secret,
        chunks: &[String],
        buttons: &[ActionButton],
        deadline: &Deadline,
    ) -> Result<ChannelResult<ExternalId>> {
        let Pairing::Paired { phone } = &state.pairing else {
            return Ok(Err(ChannelError::BindingRevoked));
        };
        if output.provider_messages.len() > chunks.len() {
            return Ok(Err(ChannelError::InvalidInput));
        }
        let mut last = output.provider_messages.last().cloned();
        for (part, text) in chunks
            .iter()
            .enumerate()
            .skip(output.provider_messages.len())
        {
            let current = self.connection(state.id.clone(), deadline).await?;
            if current.revision != state.revision {
                return Ok(Err(ChannelError::BindingRevoked));
            }
            let buttons = if part + 1 == chunks.len() {
                buttons
            } else {
                &[]
            };
            let id = match self
                .transport(state.connector)?
                .send(token, &phone.private_chat, text, buttons)
                .await
            {
                Ok(id) => id,
                Err(error) => return Ok(Err(error)),
            };
            self.finish_output(
                state,
                output,
                attempt,
                OutputOutcome::PartSent {
                    part: part as u16,
                    provider_message: id.clone(),
                },
                deadline,
            )
            .await?;
            last = Some(id);
        }
        Ok(last.ok_or(ChannelError::InvalidInput))
    }
    async fn output_text(
        &self,
        state: &Connection,
        output: &Outbound,
        deadline: &Deadline,
    ) -> Result<String> {
        if output.kind == "paired" {
            return Ok("Paired. Text here to save a message for your selected agent. Saved, notice received, Read and Replied are separate facts. Disconnect stops the channel and forgets its token on this host.".into());
        }
        if output.kind == "rejected" {
            if matches!(
                output.rejection,
                Some(se_store::channel::Rejection::Expired)
            ) {
                return Ok("No action applied: that confirmation is expired, already used or no longer matches the approved scope. Original saved mail is unchanged; approve a resume locally in StateEngine.".into());
            }
            let reason = match output.rejection {
                Some(se_store::channel::Rejection::TooLarge) => {
                    "message exceeds the 16 KiB text limit; shorten or split it"
                }
                Some(se_store::channel::Rejection::QueueFull) => {
                    "the pending queue is full; wait for it to drain before resending"
                }
                Some(se_store::channel::Rejection::Expired) => {
                    "the confirmation has expired; approve a new offer in StateEngine"
                }
                Some(se_store::channel::Rejection::Unsupported) => {
                    "only private text and current scoped confirmations are supported"
                }
                _ => return Err(channel_error(ChannelError::InvalidInput)),
            };
            return Ok(format!(
                "Not Saved: {reason}. No task or read receipt was created for this input."
            ));
        }
        let original = output
            .original
            .clone()
            .ok_or_else(|| channel_error(ChannelError::InvalidInput))?;
        let text = match output.kind.as_str() {
            "saved" => format!(
                "Saved {original}. This is saved mail, not a read or reply. Waiting for your selected agent to receive it."
            ),
            "notice" => format!(
                "Notice received for {original} in the agent's conversation. This does not mean it has read the mail or replied."
            ),
            "read" => format!(
                "Read {original} by the selected agent. Reading does not mean it accepted or completed the task."
            ),
            "resume" => format!(
                "{original} remains saved. You may confirm Start/resume for the selected agent using its preauthorized profile. This keeps any existing conversation and permissions; the offer expires in five minutes. Keep waiting requires no action."
            ),
            "resume_status" => format!(
                "Start/resume for {original} was authorized and its lifecycle reserved. Waiting for provider readiness; this is not a Read or reply."
            ),
            "resume_failed" => format!(
                "Start/resume for {original} is incomplete or its outcome is unknown. Mail remains saved. Open StateEngine to inspect the native lifecycle before trying again; no other conversation or permissions were substituted."
            ),
            "delay" => {
                let state = state.clone();
                self.read(Some(state.target.project.clone()), deadline, move |cx| {
                    let replied = !cx
                        .read
                        .channel_replies(&state.id, &original)
                        .map_err(|e| store_error(&e))?
                        .items
                        .is_empty();
                    super::status::delayed_phone_status(
                        cx.read,
                        &state.target.agent,
                        &original,
                        now()?,
                        replied,
                    )
                })
                .await?
            }
            "reply_failed" => format!(
                "A linked local reply to {original} could not be sent. Its content was retained locally or explicitly erased; inspect the reply's delivery status in StateEngine. No truncated reply was forwarded."
            ),
            "reply" => {
                let reply = output
                    .reply
                    .clone()
                    .ok_or_else(|| channel_error(ChannelError::InvalidInput))?;
                self.read(Some(state.target.project.clone()), deadline, move |cx| {
                    let message = se_core::scope::require_present(
                        cx.read.message(reply).map_err(|e| store_error(&e))?,
                        "channel reply",
                        "Inspect the committed mail reply.",
                    )?;
                    let StoredText::Present(text) = message.body else {
                        return Err(channel_error(ChannelError::ContentErased));
                    };
                    if !message.body_complete {
                        return Err(channel_error(ChannelError::MessageTooLarge));
                    }
                    Ok(format!("Reply to {original}:\n{text}"))
                })
                .await?
            }
            _ => return Err(channel_error(ChannelError::InvalidInput)),
        };
        Ok(text)
    }
    async fn finish_output(
        &self,
        state: &Connection,
        output: &Outbound,
        attempt: u64,
        outcome: OutputOutcome,
        deadline: &Deadline,
    ) -> Result<()> {
        let change = Change::OutputFinished {
            connection: state.id.clone(),
            output: output.output.clone(),
            attempt,
            outcome,
        };
        let request = intent("channel.output.finish", None, &change)?;
        // Finish an already released attempt during the normal host drain.
        // External controls remain fenced; storage closes only after workers join.
        let admission = Admission {
            scope: Scope::Project(state.target.project.clone()),
            actor: Actor::Human(self.owner.clone()),
            session: None,
            generation: self.context.generation.get(),
        };
        self.store
            .commit(admission, deadline, None, move |_, cx| {
                Ok(se_store::AtomicBatch {
                    expected_incarnation: cx.read.info().incarnation,
                    admission: cx.admission.clone(),
                    request: Some(request),
                    events: vec![event(cx, EventBody::ChannelRecorded { change })?],
                    import_checkpoint: None,
                })
            })
            .await?;
        self.changed.notify_waiters();
        Ok(())
    }
}

fn chunks(text: &str, limit: usize) -> ChannelResult<Vec<String>> {
    let mut parts = Vec::new();
    let (mut start, mut units) = (0, 0);
    for (at, ch) in text.char_indices() {
        if ch.len_utf16() > limit {
            return Err(ChannelError::MessageTooLarge);
        }
        if units + ch.len_utf16() > limit {
            parts.push(text[start..at].to_owned());
            start = at;
            units = 0;
        }
        units += ch.len_utf16();
        if parts.len() >= 32 {
            return Err(ChannelError::MessageTooLarge);
        }
    }
    if start < text.len() {
        parts.push(text[start..].to_owned());
    }
    if parts.is_empty() {
        return Err(ChannelError::InvalidInput);
    }
    Ok(parts)
}
