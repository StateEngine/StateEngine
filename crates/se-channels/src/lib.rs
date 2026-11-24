//! Owner-approved private messaging transports over the existing mail history.
//! Connect/control are native Owner operations, never agent tools or generic HTTP.
mod callback;
mod control;
mod coverage;
mod credentials;
mod delay;
mod descriptor;
mod discord;
mod error;
mod execute;
pub mod host;
mod http_client;
mod ingress;
mod inspect;
mod outbound;
mod resume;
pub mod runtime;
mod selection;
mod service;
mod status;
mod telegram;
mod transport;
mod types;
mod validation;

#[cfg(all(target_os = "linux", any(test, feature = "test-fixture")))]
#[path = "../../test-support/directory.rs"]
mod test_directory;

pub use control::{Connected, Disconnected, PairingTicket};
pub use coverage::{ReceiveCoverage, ReceiveGap, ReceiveGapReason};
pub use credentials::NativeChannelCredentials;
pub use descriptor::{ActionButton, ConnectorDescriptor, SetupField};
pub use discord::Discord;
#[cfg(all(target_os = "linux", feature = "test-fixture"))]
pub use discord::test_fixture as discord_test_fixture;
pub use error::{ChannelError, ChannelResult};
pub use execute::ChannelExecution;
pub use host::{
    AsChannelDeadline, BoxedBlockingWork, BoxedReadWork, ChannelDeadline, ChannelHost, HostFuture,
};
pub use service::{Channels, ReceiverIntervals};
pub use telegram::Telegram;
pub use transport::{
    ChannelReceiver, ChannelTransport, Incoming, IncomingContent, TransportFuture,
};
pub use types::*;
pub use validation::CHANNEL_CONSENT;
