//! Verified provider identity becomes only the exact paired Owner's mail.
//! Provider offsets are read from committed dispositions, never local counters.
use super::{service::*, *};
use crate::client::lease::Deadline;
use se_core::{
    commit::{CoreOps, MessageKind, MessageSend, OpStep},
    dispatch::Kernel,
    store_error::store_error,
};
use se_store::{
    EventBody, Snapshot,
    channel::{Change, Connection, Disposition, Pairing, Rejection},
};
use se_types::{IdempotencyKey, Result};
use sha2::{Digest, Sha256};

impl Channels {
    pub(super) async fn handle_update(
        &self,
        state: Connection,
        input: Incoming,
        deadline: &Deadline,
    ) -> Result<()> {
        let id = state.id.clone();
        let update = input.update;
        if self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read
                    .channel_update_handled(&id, update)
                    .map_err(|e| store_error(&e))
            })
            .await?
        {
            return Ok(());
        }
        let key = IdempotencyKey::new(format!("telegram-update-{}-{}", state.id, input.update))
            .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        // The fingerprint binds the normalized provider input without retaining
        // its body in channel metadata. Its ordinary mail body is stored once.
        let fingerprint = match &input.content {
            IncomingContent::Text { phone, text } => {
                serde_json::json!({"connection":state.id,"binding_revision":state.revision,"update":input.update,"subject":phone.subject,"chat":phone.private_chat,"text_sha256":se_types::hex_lower(&Sha256::digest(text.as_bytes()))})
            }
            IncomingContent::Callback {
                phone,
                data,
                callback_id,
            } => {
                serde_json::json!({"connection":state.id,"binding_revision":state.revision,"update":input.update,"subject":phone.subject,"chat":phone.private_chat,"callback_sha256":se_types::hex_lower(&Sha256::digest(data.as_bytes())),"callback_id":callback_id})
            }
            IncomingContent::UnsupportedPrivate { phone } => {
                serde_json::json!({"connection":state.id,"binding_revision":state.revision,"update":input.update,"subject":phone.subject,"chat":phone.private_chat,"unsupported_private":true})
            }
            IncomingContent::Unsupported => {
                serde_json::json!({"connection":state.id,"binding_revision":state.revision,"update":input.update,"unsupported":true})
            }
        };
        let request = intent("channel.update", key.clone(), &fingerprint)?;
        if self
            .replay(state.target.project.clone(), request.clone(), deadline)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let update = input.update;
        if self
            .confirm_resume(&state, &input.content, &request, update, deadline)
            .await?
        {
            return Ok(());
        }
        if let IncomingContent::Text { phone, text } = &input.content
            && let Pairing::Challenge {
                digest,
                expires_at_us,
            } = &state.pairing
            && let Some(challenge) = text.strip_prefix("/start ")
            && challenge.len() == 64
            && Sha256::digest(challenge.as_bytes()).as_slice() == digest
            && *expires_at_us > now()?
        {
            let change = Change::PairingSeen {
                connection: state.id.clone(),
                expected: state.revision,
                digest: *digest,
                phone: phone.clone(),
            };
            let handled = Change::UpdateHandled {
                connection: state.id.clone(),
                binding_revision: state.revision + 1,
                update,
                disposition: Disposition::Rejected {
                    reason: Rejection::Unpaired,
                },
            };
            self.commit(state.target.project, request, deadline, move |cx| {
                Ok(vec![
                    event(cx, EventBody::ChannelRecorded { change })?,
                    event(cx, EventBody::ChannelRecorded { change: handled })?,
                ])
            })
            .await?;
            return Ok(());
        }
        let callback_id = match &input.content {
            IncomingContent::Callback { callback_id, .. } => Some(callback_id.clone()),
            _ => None,
        };
        let (phone, text, callback_rejection) = match input.content {
            IncomingContent::Text { phone, text } => (Some(phone), Some(text), None),
            IncomingContent::Callback { phone, data, .. } => (
                Some(phone),
                None,
                Some(if data.starts_with("r:") {
                    Rejection::Expired
                } else {
                    Rejection::Unsupported
                }),
            ),
            IncomingContent::UnsupportedPrivate { phone } => {
                (Some(phone), None, Some(Rejection::Unsupported))
            }
            _ => (None, None, None),
        };
        let mut rejected = match (&state.pairing, &phone, &text) {
            (Pairing::Paired { phone: approved }, Some(phone), Some(text))
                if approved.subject == phone.subject
                    && approved.private_chat == phone.private_chat =>
            {
                if text.len() > se_store::channel::MAX_TEXT_BYTES {
                    Some(Rejection::TooLarge)
                } else if text.is_empty() {
                    Some(Rejection::Unsupported)
                } else {
                    None
                }
            }
            (Pairing::Paired { phone: approved }, Some(phone), None)
                if approved.subject == phone.subject
                    && approved.private_chat == phone.private_chat =>
            {
                Some(callback_rejection.unwrap_or(Rejection::Unsupported))
            }
            (Pairing::Revoked, _, _) => Some(Rejection::Revoked),
            (_, None, _) => Some(Rejection::Unsupported),
            _ => Some(Rejection::Unpaired),
        };
        if rejected.is_none() {
            let id = state.id.clone();
            if !self
                .read(Some(state.target.project.clone()), deadline, move |cx| {
                    cx.read
                        .channel_has_capacity(&id)
                        .map_err(|e| store_error(&e))
                })
                .await?
            {
                rejected = Some(Rejection::QueueFull);
            }
        }
        if let Some(reason) = rejected {
            let disposition = match (&state.pairing, &phone) {
                (Pairing::Paired { phone: approved }, Some(phone))
                    if approved.subject == phone.subject
                        && approved.private_chat == phone.private_chat =>
                {
                    Disposition::RejectedPaired {
                        reason,
                        subject: phone.subject,
                        private_chat: phone.private_chat,
                    }
                }
                _ => Disposition::Rejected { reason },
            };
            let acknowledge = matches!(disposition, Disposition::RejectedPaired { .. });
            self.change(
                state.target.project.clone(),
                request,
                Change::UpdateHandled {
                    connection: state.id.clone(),
                    binding_revision: state.revision,
                    update,
                    disposition,
                },
                deadline,
            )
            .await?;
            if acknowledge && let Some(callback_id) = callback_id {
                self.ack_callback(&state, &callback_id, false, deadline)
                    .await?;
            }
            return Ok(());
        }
        let phone = phone.ok_or_else(|| channel_error(ChannelError::InvalidInput))?;
        let body = text.ok_or_else(|| channel_error(ChannelError::InvalidInput))?;
        let saved_state = state.clone();
        let committed = self
            .commit(state.target.project.clone(), request, deadline, move |cx| {
                let facts = crate::runtime::start::allocate_facts()?;
                let message = facts.message.clone();
                let kernel = Kernel::new(facts)?;
                let send = MessageSend {
                    to: state.target.agent.to_string(),
                    body,
                    quiet: false,
                    kind: MessageKind::Task,
                    refs: vec![],
                    reply_to: None,
                    work: None,
                    idempotency_key: key,
                };
                let OpStep::Commit { mut batch, .. } = kernel.message_send(send, cx)? else {
                    return Err(channel_error(ChannelError::InvalidInput));
                };
                let random = se_proc::random_secret()
                    .map_err(|_| channel_error(ChannelError::CredentialStoreUnavailable))?;
                let receipt = ReceiptId::new(format!(
                    "chr-{}",
                    se_types::hex_lower(&random.expose()[..16])
                ))
                .map_err(|_| channel_error(ChannelError::InvalidInput))?;
                batch.events.push(event(
                    cx,
                    EventBody::ChannelRecorded {
                        change: Change::UpdateHandled {
                            connection: state.id,
                            binding_revision: state.revision,
                            update,
                            disposition: Disposition::Saved {
                                receipt,
                                message,
                                subject: phone.subject,
                                private_chat: phone.private_chat,
                            },
                        },
                    },
                )?);
                Ok(batch.events)
            })
            .await?;
        if let Change::UpdateHandled {
            disposition: Disposition::Saved { message, .. },
            ..
        } = self
            .committed_change(saved_state.target.project.clone(), &committed, deadline)
            .await?
        {
            self.offer_resume(&saved_state, message, deadline).await?;
        }
        Ok(())
    }
    pub(super) async fn poll_once(&self, id: ChannelId, deadline: &Deadline) -> Result<()> {
        let state = self.connection(id.clone(), deadline).await?;
        if matches!(state.pairing, Pairing::Revoked) {
            return Err(channel_error(ChannelError::BindingRevoked));
        }
        let credential = state.credential.clone();
        let credentials = self.credentials.clone();
        let token = self
            .context
            .blocking
            .run(crate::BlockingClass::Foreground, deadline, move || {
                credentials.resolve(&credential).map_err(channel_error)
            })
            .await?;
        let offset = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read.channel_offset(&id).map_err(|e| store_error(&e))
            })
            .await?;
        let updates = match self.telegram.poll(&token, offset).await {
            Ok(updates) => updates,
            Err(error) => {
                let seconds = match error {
                    ChannelError::RateLimited {
                        retry_after_seconds,
                    } => retry_after_seconds,
                    _ => 60,
                };
                self.set_health(
                    state.id.clone(),
                    ConnectionHealth::Retrying {
                        code: error.code().into(),
                        retry_at_us: now()?.saturating_add(i64::from(seconds) * 1_000_000),
                    },
                )?;
                return Err(channel_error(error));
            }
        };
        for input in updates {
            let current = self.connection(state.id.clone(), deadline).await?;
            self.handle_update(current, input, deadline).await?;
        }
        self.set_health(
            state.id,
            ConnectionHealth::Connected {
                last_poll_at_us: Some(now()?),
            },
        )?;
        Ok(())
    }
}
