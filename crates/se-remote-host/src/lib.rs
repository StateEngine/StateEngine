//! Target-side remote host listener, device/source authorization, key and binding
//! custody, live observation publishing, and cursor/view-request codecs.
pub mod auth;
pub mod bindings;
pub mod cursor;
pub mod keys;
pub mod listener;
pub mod ports;
pub mod publish;
pub mod session;
pub mod view_request;

pub use ports::{BlockingRunner, WriterFaultObserver, run_foreground, run_owned};
pub use se_remote::{
    ClientConnectionId, CredentialSource, RemoteCallContext, RemoteClient, RemoteConnector,
    RemoteFuture, RemoteRoute, RemoteWatchStream, channel, entropy, ssh, transport_io, wire,
};
pub use se_types::Result;
pub use se_types::remote::*;
pub use session::{SecurityStore, event_id, now};
