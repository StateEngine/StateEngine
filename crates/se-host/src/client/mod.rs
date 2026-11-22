//! Synchronous CLI/hook bootstrap and IPC client contract. This module and its
//! transitive declarations build with --no-default-features and no Tokio.
pub use se_harness::ClientOptions;
pub struct BlockingIpcClient {
    pub(crate) _private: (),
}
pub use lease::{BlockingConnection, ExchangeProgress};
pub mod auth;
pub mod closure;
pub mod endpoint;
pub mod lease;
pub mod operation;
pub mod presence;
#[path = "../rebind/wire.rs"]
pub mod rebind;
pub mod wire;

pub mod hello;
