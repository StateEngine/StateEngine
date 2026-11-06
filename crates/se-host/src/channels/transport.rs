//! Normalized provider adapter. It supplies provider facts, never Owner authority.
use super::*;
use se_types::Secret;
use std::{future::Future, pin::Pin};
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = ChannelResult<T>> + Send + 'a>>;
pub trait ChannelTransport: Send + Sync {
    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity>;
    fn poll<'a>(
        &'a self,
        token: &'a Secret,
        offset: Option<i64>,
    ) -> TransportFuture<'a, Vec<Incoming>>;
    fn answer_callback<'a>(
        &'a self,
        token: &'a Secret,
        id: &'a str,
        accepted: bool,
    ) -> TransportFuture<'a, ()>;
    fn send<'a>(
        &'a self,
        token: &'a Secret,
        chat: i64,
        text: &'a str,
        keyboard: Option<serde_json::Value>,
    ) -> TransportFuture<'a, i64>;
}
impl ChannelTransport for Telegram {
    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity> {
        Box::pin(Telegram::identity(self, token))
    }
    fn poll<'a>(
        &'a self,
        token: &'a Secret,
        offset: Option<i64>,
    ) -> TransportFuture<'a, Vec<Incoming>> {
        Box::pin(Telegram::poll(self, token, offset))
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
        chat: i64,
        text: &'a str,
        keyboard: Option<serde_json::Value>,
    ) -> TransportFuture<'a, i64> {
        Box::pin(Telegram::send(self, token, chat, text, keyboard))
    }
}
impl crate::HostedRuntime {
    /// Trusted in-process adapter installation, before serving or constructing
    /// Channels. No wire request, model tool or remote client can replace it.
    pub fn install_channel_transport(
        &mut self,
        transport: std::sync::Arc<dyn ChannelTransport>,
    ) -> se_types::Result<()> {
        if self.phase != crate::HostPhase::Prepared || self.channels.get().is_some() {
            return Err(se_types::SeError::invalid(
                "channel transport",
                "installation before Channels construction and listener publication",
            ));
        }
        if self.channel_transport.is_some() {
            return Err(se_types::SeError::invalid(
                "channel transport",
                "one startup adapter installation",
            ));
        }
        self.channel_transport = Some(transport);
        Ok(())
    }
}
