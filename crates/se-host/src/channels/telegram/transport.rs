//! Telegram alone owns numeric offsets and its private polling protocol.
use super::*;
use crate::channels::*;
use std::collections::VecDeque;

struct Receiver {
    transport: Telegram,
    offset: Option<i64>,
    pending: Option<ReceiveCursor>,
    ready: VecDeque<Incoming>,
}
fn next_offset(cursor: &ReceiveCursor) -> ChannelResult<i64> {
    cursor
        .as_str()
        .parse::<i64>()
        .ok()
        .filter(|v| *v >= 0)
        .and_then(|v| v.checked_add(1))
        .ok_or(Error::InvalidInput)
}
impl ChannelReceiver for Receiver {
    fn next<'a>(&'a mut self, token: &'a Secret) -> TransportFuture<'a, Option<Incoming>> {
        Box::pin(async move {
            if self.pending.is_some() {
                return Err(Error::InvalidInput);
            }
            if self.ready.is_empty() {
                self.ready = self.transport.poll(token, self.offset).await?.into();
            }
            let next = self.ready.pop_front();
            self.pending = next.as_ref().map(|value| value.cursor.clone());
            Ok(next)
        })
    }
    fn ack(&mut self, cursor: &ReceiveCursor) -> ChannelResult<()> {
        if self.pending.as_ref() != Some(cursor) {
            return Err(Error::InvalidInput);
        }
        self.offset = Some(next_offset(cursor)?);
        self.pending = None;
        Ok(())
    }
}
impl ChannelTransport for Telegram {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: Connector::Telegram,
            name: "Telegram",
            max_text_utf16: 4096,
            edits: false,
            buttons: true,
            threads: false,
            media: false,
            identity_proof: "authenticated_private_sender",
            acknowledgement: "cursor_after_durable_save",
            reconnect: "provider_replay",
            retention_seconds: Some(86_400),
            setup: &[SetupField {
                key: "token",
                label: "Bot token",
                secret: true,
                required: true,
            }],
            instructions: "Create a bot, enter its token in the protected credential field, then open the pairing link and approve the shown private sender.",
        }
    }
    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity> {
        Box::pin(Telegram::identity(self, token))
    }
    fn receiver(
        self: std::sync::Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>> {
        let offset = cursor.as_ref().map(next_offset).transpose()?;
        Ok(Box::new(Receiver {
            transport: (*self).clone(),
            offset,
            pending: None,
            ready: VecDeque::new(),
        }))
    }
    fn pairing_link(&self, bot: &BotIdentity, challenge: &str) -> ChannelResult<Secret> {
        Secret::new(format!("https://t.me/{}?start={challenge}", bot.username).into_bytes())
            .map_err(|_| Error::InvalidInput)
    }
    fn answer_callback<'a>(
        &'a self,
        token: &'a Secret,
        id: &'a str,
        accepted: bool,
    ) -> TransportFuture<'a, ()> {
        Box::pin(Telegram::answer_callback(self, token, id, accepted))
    }
    fn send<'a>(
        &'a self,
        token: &'a Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId> {
        Box::pin(async move {
            let chat = chat.as_str().parse().map_err(|_| Error::InvalidInput)?;
            let keyboard = (!buttons.is_empty()).then(|| json!({"inline_keyboard": buttons.iter().map(|b| vec![json!({"text": b.label, "callback_data": b.data})]).collect::<Vec<_>>()}));
            Telegram::send(self, token, chat, text, keyboard)
                .await
                .map(Into::into)
        })
    }
}
