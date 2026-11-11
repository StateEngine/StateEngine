//! Owner-approved private messaging transports over the existing mail history.
//! Connect/control are native Owner operations, never agent tools or generic HTTP.
#[cfg(feature = "listener")]
mod callback;
#[cfg(feature = "listener")]
mod control;
#[cfg(feature = "listener")]
mod delay;
mod descriptor;
#[cfg(feature = "listener")]
mod ingress;
#[cfg(feature = "listener")]
mod inspect;
#[cfg(feature = "listener")]
mod outbound;
#[cfg(feature = "listener")]
mod resume;
#[cfg(feature = "listener")]
pub(crate) mod runtime;
#[cfg(feature = "listener")]
mod selection;
#[cfg(feature = "listener")]
mod service;
#[cfg(feature = "listener")]
mod status;
mod types;
pub use descriptor::{ActionButton, ConnectorDescriptor, SetupField};
mod validation;
#[cfg(feature = "listener")]
pub use control::{Connected, Disconnected, PairingTicket};
#[cfg(feature = "listener")]
pub use service::Channels;
pub use validation::CHANNEL_CONSENT;
mod coverage;
pub use coverage::{ReceiveCoverage, ReceiveGap, ReceiveGapReason};
mod credentials;
#[cfg(feature = "listener")]
mod discord;
mod error;
#[cfg(feature = "listener")]
mod telegram;
#[cfg(feature = "listener")]
mod transport;
pub use credentials::NativeChannelCredentials;
#[cfg(feature = "listener")]
pub use discord::Discord;
pub use error::{ChannelError, ChannelResult};
#[cfg(feature = "listener")]
pub use telegram::Telegram;
#[cfg(feature = "listener")]
pub use transport::{
    ChannelReceiver, ChannelTransport, Incoming, IncomingContent, TransportFuture,
};
pub use types::*;
