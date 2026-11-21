//! Verified provider identity becomes only the exact paired Owner's mail.
//! Provider cursors are read from committed dispositions, never local counters.
use super::{service::*, *};
use crate::host::ChannelDeadline as Deadline;
use se_core::{
    commit::{CoreOps, MessageKind, MessageSend, OpStep},
    dispatch::Kernel,
    store_error::store_error,
};
use se_store::{
    CommitReceipt, EventBody, RequestIdentity, Snapshot,
    channel::{Change, Connection, Disposition, Pairing, Rejection},
};
use se_types::{IdempotencyKey, Result};
use sha2::{Digest, Sha256};

struct SavedMail {
    phone: PhoneIdentity,
    body: String,
    key: IdempotencyKey,
}
impl Channels {
    pub(super) async fn handle_update(
        &self,
        state: Connection,
        mut input: Incoming,
        deadline: &Deadline,
    ) -> Result<()> {
        let update = input.update.clone();
        let handled = self.update_handled(&state, &update, deadline).await?;
        if handled {
            return Ok(());
        }
        normalize_confirm(&mut input.content);
        let key = update_key(&state, &input)?;
        // The fingerprint binds the normalized provider input without retaining
        // its body in channel metadata. Its ordinary mail body is stored once.
        let fingerprint = update_fingerprint(&state, &input);
        let request = intent("channel.update", key.clone(), &fingerprint)?;
        if self
            .replay(state.target.project.clone(), request.clone(), deadline)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let update = input.update.clone();
        if self
            .confirm_resume(
                &state,
                &input.content,
                &request,
                update.clone(),
                input.cursor.clone(),
                deadline,
            )
            .await?
        {
            return Ok(());
        }
        if self
            .consume_pairing_challenge(&state, &input, &request, deadline)
            .await?
        {
            return Ok(());
        }
        let (callback_id, phone, text, callback_rejection) = content_parts(&input.content);
        let mut rejected = pairing_rejection(
            &state.pairing,
            phone.as_ref(),
            text.as_ref(),
            callback_rejection,
        );
        if rejected.is_none()
            && !self
                .channel_capacity(&state.target.project, state.id.clone(), deadline)
                .await?
        {
            rejected = Some(Rejection::QueueFull);
        }
        if let Some(reason) = rejected {
            let (disposition, acknowledge) =
                rejection_disposition(&state.pairing, reason, phone.as_ref());
            self.change(
                state.target.project.clone(),
                request,
                Change::UpdateHandled {
                    connection: state.id.clone(),
                    binding_revision: state.revision,
                    update,
                    cursor: Some(input.cursor.clone()),
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
            .commit_saved_mail(
                state,
                input,
                SavedMail { phone, body, key },
                request,
                deadline,
            )
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
    async fn update_handled(
        &self,
        state: &Connection,
        update: &ExternalId,
        deadline: &Deadline,
    ) -> Result<bool> {
        let project = state.target.project.clone();
        let id = state.id.clone();
        let update = update.clone();
        self.read(Some(project), deadline, move |cx| {
            cx.read
                .channel_update_handled(&id, &update)
                .map_err(|e| store_error(&e))
        })
        .await
    }
    async fn channel_capacity(
        &self,
        project: &se_types::ProjectId,
        id: ChannelId,
        deadline: &Deadline,
    ) -> Result<bool> {
        self.read(Some(project.clone()), deadline, move |cx| {
            cx.read
                .channel_has_capacity(&id)
                .map_err(|e| store_error(&e))
        })
        .await
    }
    async fn consume_pairing_challenge(
        &self,
        state: &Connection,
        input: &Incoming,
        request: &RequestIdentity,
        deadline: &Deadline,
    ) -> Result<bool> {
        let update = input.update.clone();
        if let IncomingContent::Text { phone, text } = &input.content
            && let Pairing::Challenge {
                digest,
                expires_at_us,
            } = &state.pairing
            && let Some(challenge) = text.strip_prefix("/start ")
            && challenge.len() == 64
            && bool::from(subtle::ConstantTimeEq::ct_eq(
                Sha256::digest(challenge.as_bytes()).as_slice(),
                digest.as_slice(),
            ))
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
                cursor: Some(input.cursor.clone()),
                disposition: Disposition::Rejected {
                    reason: Rejection::Unpaired,
                },
            };
            self.commit(
                state.target.project.clone(),
                request.clone(),
                deadline,
                move |cx| {
                    Ok(vec![
                        event(cx, EventBody::ChannelRecorded { change })?,
                        event(cx, EventBody::ChannelRecorded { change: handled })?,
                    ])
                },
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }
    async fn commit_saved_mail(
        &self,
        state: Connection,
        input: Incoming,
        save: SavedMail,
        request: RequestIdentity,
        deadline: &Deadline,
    ) -> Result<CommitReceipt> {
        let update = input.update.clone();
        self.commit(state.target.project.clone(), request, deadline, move |cx| {
            let facts = super::service::allocate_facts()?;
            let message = facts.message.clone();
            let kernel = Kernel::new(facts)?;
            let send = MessageSend {
                to: Some(state.target.agent.to_string()),
                body: save.body,
                quiet: false,
                kind: MessageKind::Task,
                refs: vec![],
                reply_to: None,
                supersedes: None,
                work: None,
                idempotency_key: save.key,
            };
            let OpStep::Commit { mut batch, .. } = kernel.message_send(send, cx)? else {
                return Err(channel_error(ChannelError::InvalidInput));
            };
            let random = se_proc::random_secret().map_err(store_unavailable)?;
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
                        cursor: Some(input.cursor.clone()),
                        disposition: Disposition::Saved {
                            receipt,
                            message,
                            subject: save.phone.subject.clone(),
                            private_chat: save.phone.private_chat.clone(),
                        },
                    },
                },
            )?);
            Ok(batch.events)
        })
        .await
    }
    pub(super) async fn receive_once(
        &self,
        id: ChannelId,
        receiver: &mut Option<Box<dyn ChannelReceiver>>,
        deadline: &Deadline,
    ) -> Result<bool> {
        let state = self.connection(id.clone(), deadline).await?;
        if matches!(state.pairing, Pairing::Revoked) {
            return Err(channel_error(ChannelError::BindingRevoked));
        }
        let token = self.token(state.credential.clone(), deadline).await?;
        if receiver.is_none() {
            let cursor = self
                .read(Some(state.target.project.clone()), deadline, move |cx| {
                    cx.read.channel_cursor(&id).map_err(|e| store_error(&e))
                })
                .await?;
            *receiver = Some(
                self.transport(state.connector)?
                    .receiver(cursor)
                    .map_err(channel_error)?,
            );
        }
        let receiver = receiver
            .as_mut()
            .ok_or_else(|| channel_error(ChannelError::ReceiverNotRunning))?;
        let input = match tokio::time::timeout(deadline.remaining()?, receiver.next(&token)).await {
            Ok(Ok(input)) => input,
            outcome => {
                let error = match outcome {
                    Ok(Err(error)) => error,
                    _ => ChannelError::ProviderUnreachable,
                };
                let seconds = match error {
                    ChannelError::RateLimited {
                        retry_after_seconds,
                    } => retry_after_seconds,
                    _ => 1,
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
        let received = input.is_some();
        if let Some(input) = input {
            let current = self.connection(state.id.clone(), deadline).await?;
            if current.revision != state.revision {
                return Err(channel_error(ChannelError::RevisionConflict));
            }
            let cursor = input.cursor.clone();
            let update = input.update.clone();
            self.handle_update(current, input, deadline).await?;
            // Replayed dispositions can carry an older cursor. Commit this
            // delivery checkpoint before ACK, using the revision after pairing.
            let current = self.connection(state.id.clone(), deadline).await?;
            let change = Change::CursorAdvanced {
                connection: current.id,
                binding_revision: current.revision,
                update,
                cursor: cursor.clone(),
            };
            self.change(
                current.target.project,
                intent("channel.receive.advance", None, &change)?,
                change,
                deadline,
            )
            .await?;
            receiver.ack(&cursor).map_err(channel_error)?;
        }
        self.set_health(
            state.id,
            ConnectionHealth::Connected {
                last_poll_at_us: Some(now()?),
            },
        )?;
        Ok(received)
    }
}
fn normalize_confirm(content: &mut IncomingContent) {
    if let IncomingContent::Text { phone, text } = content
        && let Some(data) = text.strip_prefix("/confirm ")
    {
        *content = IncomingContent::Callback {
            phone: phone.clone(),
            data: data.into(),
            callback_id: None,
        };
    }
}
fn update_key(state: &Connection, input: &Incoming) -> Result<IdempotencyKey> {
    IdempotencyKey::new(format!(
        "{}-update-{}-{}",
        state.connector.as_str(),
        state.id,
        se_types::hex_lower(&Sha256::digest(input.update.as_str().as_bytes()))
    ))
    .map_err(|_| channel_error(ChannelError::InvalidInput))
}
fn update_fingerprint(state: &Connection, input: &Incoming) -> serde_json::Value {
    match &input.content {
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
    }
}
fn content_parts(
    content: &IncomingContent,
) -> (
    Option<String>,
    Option<PhoneIdentity>,
    Option<String>,
    Option<Rejection>,
) {
    match content {
        IncomingContent::Text { phone, text } => {
            (None, Some(phone.clone()), Some(text.clone()), None)
        }
        IncomingContent::Callback {
            phone,
            data,
            callback_id,
        } => (
            callback_id.clone(),
            Some(phone.clone()),
            None,
            Some(if data.starts_with("r:") {
                Rejection::Expired
            } else {
                Rejection::Unsupported
            }),
        ),
        IncomingContent::UnsupportedPrivate { phone } => (
            None,
            Some(phone.clone()),
            None,
            Some(Rejection::Unsupported),
        ),
        _ => (None, None, None, None),
    }
}
fn pairing_rejection(
    pairing: &Pairing,
    phone: Option<&PhoneIdentity>,
    text: Option<&String>,
    callback_rejection: Option<Rejection>,
) -> Option<Rejection> {
    match (pairing, phone, text) {
        (Pairing::Paired { phone: approved }, Some(phone), Some(text))
            if approved.subject == phone.subject && approved.private_chat == phone.private_chat =>
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
            if approved.subject == phone.subject && approved.private_chat == phone.private_chat =>
        {
            Some(callback_rejection.unwrap_or(Rejection::Unsupported))
        }
        (Pairing::Revoked, _, _) => Some(Rejection::Revoked),
        (_, None, _) => Some(Rejection::Unsupported),
        _ => Some(Rejection::Unpaired),
    }
}
fn rejection_disposition(
    pairing: &Pairing,
    reason: Rejection,
    phone: Option<&PhoneIdentity>,
) -> (Disposition, bool) {
    let disposition = match (pairing, phone) {
        (Pairing::Paired { phone: approved }, Some(phone))
            if approved.subject == phone.subject && approved.private_chat == phone.private_chat =>
        {
            Disposition::RejectedPaired {
                reason,
                subject: phone.subject.clone(),
                private_chat: phone.private_chat.clone(),
            }
        }
        _ => Disposition::Rejected { reason },
    };
    let acknowledge = matches!(disposition, Disposition::RejectedPaired { .. });
    (disposition, acknowledge)
}
