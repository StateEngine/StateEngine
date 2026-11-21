//! Normalized connector facts never grant Owner authority.
use super::*;
use se_types::Secret;
use std::{future::Future, pin::Pin};
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = ChannelResult<T>> + Send + 'a>>;
#[derive(Clone)]
pub struct Incoming {
    pub update: ExternalId,
    pub cursor: ReceiveCursor,
    pub content: IncomingContent,
}
#[derive(Clone)]
pub enum IncomingContent {
    Text {
        phone: PhoneIdentity,
        text: String,
    },
    Callback {
        phone: PhoneIdentity,
        data: String,
        callback_id: Option<String>,
    },
    UnsupportedPrivate {
        phone: PhoneIdentity,
    },
    Unsupported,
}
/// The receiver may advance its provider acknowledgement only after the host's
/// durable disposition and checkpoint commit. Reconnect starts from that cursor.
pub trait ChannelReceiver: Send {
    fn next<'a>(&'a mut self, token: &'a Secret) -> TransportFuture<'a, Option<Incoming>>;
    fn ack(&mut self, cursor: &ReceiveCursor) -> ChannelResult<()>;
}
pub trait ChannelTransport: Send + Sync {
    fn descriptor(&self) -> ConnectorDescriptor;
    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity>;
    fn receiver(
        self: std::sync::Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>>;
    fn pairing_link(&self, bot: &BotIdentity, challenge: &str) -> ChannelResult<Secret>;
    fn answer_callback<'a>(
        &'a self,
        token: &'a Secret,
        id: &'a str,
        accepted: bool,
    ) -> TransportFuture<'a, ()>;
    fn send<'a>(
        &'a self,
        token: &'a Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId>;
}
