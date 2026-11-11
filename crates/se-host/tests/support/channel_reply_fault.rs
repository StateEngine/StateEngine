//! Only provider sends are substituted; the host, MCP and commit path are real.
use crate::transport::Transport;
use se_host::channels::*;
use se_types::Secret;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Default)]
pub struct FirstReplyGate {
    entered: Notify,
    release: Notify,
}
impl FirstReplyGate {
    pub async fn entered(&self) {
        self.entered.notified().await;
    }
    pub fn release(&self) {
        self.release.notify_one();
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    Complete,
    UnknownSecond,
    FailedSecond,
    RateLimitedSecond,
}
struct Reply {
    expected: String,
    offset: usize,
    mode: Mode,
    fired: bool,
    attempts: Vec<String>,
    accepted: Vec<String>,
}
#[derive(Default)]
pub struct FaultTransport {
    inner: Arc<Transport>,
    reply: Mutex<Option<Reply>>,
    first_reply_gate: Mutex<Option<Arc<FirstReplyGate>>>,
}
impl std::ops::Deref for FaultTransport {
    type Target = Transport;
    fn deref(&self) -> &Transport {
        &self.inner
    }
}
impl FaultTransport {
    pub fn gate_first_reply(&self) -> ChannelResult<Arc<FirstReplyGate>> {
        let gate = Arc::new(FirstReplyGate::default());
        *self
            .first_reply_gate
            .lock()
            .map_err(|_| ChannelError::ReceiverNotRunning)? = Some(gate.clone());
        Ok(gate)
    }
    pub fn arm(&self, expected: String, mode: Mode) -> ChannelResult<()> {
        *self
            .reply
            .lock()
            .map_err(|_| ChannelError::ReceiverNotRunning)? = Some(Reply {
            expected,
            offset: 0,
            mode,
            fired: false,
            attempts: vec![],
            accepted: vec![],
        });
        Ok(())
    }
    pub fn observations(&self) -> ChannelResult<(Vec<String>, Vec<String>)> {
        let reply = self
            .reply
            .lock()
            .map_err(|_| ChannelError::ReceiverNotRunning)?;
        let reply = reply.as_ref().ok_or(ChannelError::InvalidInput)?;
        Ok((reply.attempts.clone(), reply.accepted.clone()))
    }
}
impl ChannelTransport for FaultTransport {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.inner.descriptor()
    }
    fn receiver(
        self: Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>> {
        self.inner.clone().receiver(cursor)
    }
    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity> {
        self.inner.identity(token)
    }
    fn pairing_link(&self, bot: &BotIdentity, challenge: &str) -> ChannelResult<Secret> {
        self.inner.pairing_link(bot, challenge)
    }
    fn answer_callback<'a>(
        &'a self,
        token: &'a Secret,
        id: &'a str,
        accepted: bool,
    ) -> TransportFuture<'a, ()> {
        self.inner.answer_callback(token, id, accepted)
    }
    fn send<'a>(
        &'a self,
        token: &'a Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId> {
        Box::pin(async move {
            let gate = if text.starts_with("Reply to ") {
                self.first_reply_gate
                    .lock()
                    .map_err(|_| ChannelError::ReceiverNotRunning)?
                    .take()
            } else {
                None
            };
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            let decision = {
                let mut reply = self
                    .reply
                    .lock()
                    .map_err(|_| ChannelError::ReceiverNotRunning)?;
                match reply.as_mut() {
                    Some(reply)
                        if !text.is_empty() && reply.expected[reply.offset..].starts_with(text) =>
                    {
                        reply.attempts.push(text.into());
                        let fault = reply.accepted.len() == 1 && !reply.fired;
                        reply.fired |= fault;
                        Some(if fault { reply.mode } else { Mode::Complete })
                    }
                    _ => None,
                }
            };
            match decision {
                Some(Mode::FailedSecond) => return Err(ChannelError::MessageTooLarge),
                Some(Mode::RateLimitedSecond) => {
                    return Err(ChannelError::RateLimited {
                        retry_after_seconds: 1,
                    });
                }
                _ => {}
            }
            let result = self.inner.send(token, chat, text, buttons).await;
            if decision.is_some() && result.is_ok() {
                let mut reply = self
                    .reply
                    .lock()
                    .map_err(|_| ChannelError::ReceiverNotRunning)?;
                let reply = reply.as_mut().ok_or(ChannelError::InvalidInput)?;
                reply.offset += text.len();
                reply.accepted.push(text.into());
            }
            if decision == Some(Mode::UnknownSecond) && result.is_ok() {
                // The provider accepted this part, but its response was lost.
                return Err(ChannelError::SendOutcomeUnknown);
            }
            result
        })
    }
}
