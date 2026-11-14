//! Shared optional remote-client seams. Declaring these values starts no task,
//! listener, timer or allocation. Design 45 §§3–6 and 47 §§5/9 govern consumers.
#[cfg(feature = "remote")]
use se_types::Result;
#[cfg(feature = "remote")]
use std::sync::Arc;
#[cfg(feature = "remote")]
pub(crate) mod activity;
#[cfg(feature = "remote")]
mod channel;
#[cfg(feature = "remote")]
pub mod client;
#[cfg(feature = "remote")]
pub(crate) mod control;
#[cfg(feature = "remote")]
mod native_image;
#[cfg(feature = "remote")]
pub mod ssh;
#[cfg(feature = "remote")]
mod ssh_diagnostic;
#[cfg(feature = "remote")]
pub use control::{BootstrapSession, startup_notice};
#[cfg(feature = "remote")]
mod cursor;
#[cfg(feature = "remote")]
pub mod listener;
#[cfg(feature = "remote")]
pub mod publish;
#[cfg(feature = "remote")]
pub mod service;
#[cfg(feature = "remote")]
pub use client::ClientConnector;
mod owner_input;
#[cfg(feature = "remote")]
pub(crate) use owner_input::OwnerCall;
pub use owner_input::OwnerInput;
#[cfg(feature = "remote")]
pub use owner_input::{LaunchPermissionChange, SourcePermissionChange};
pub mod session;
pub use se_remote::RemoteCallContext;
#[cfg(feature = "remote")]
pub(crate) use se_remote::transport_io;
#[cfg(feature = "remote")]
pub use se_remote::wire;
pub use se_remote::{
    ClientConnectionId, CredentialSource, RemoteClient, RemoteConnector, RemoteFuture, RemoteRoute,
    RemoteWatchStream,
};
pub use se_types::remote::*;

#[cfg(feature = "remote")]
pub mod auth;
#[cfg(feature = "remote")]
pub mod keys;

#[cfg(feature = "remote")]
pub mod read;

#[cfg(feature = "remote")]
pub mod bindings;
#[cfg(feature = "listener")]
pub mod broker;

#[cfg(feature = "remote")]
pub(crate) mod view_request;
