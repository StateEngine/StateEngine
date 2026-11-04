//! Synchronous CLI/hook bootstrap and IPC client contract. This module and its
//! transitive declarations build with --no-default-features and no Tokio.
use se_types::Generation;
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub struct ClientOptions {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancelled: Arc<AtomicBool>,
}
pub struct BlockingIpcClient {
    pub(crate) _private: (),
}
pub use lease::{BlockingConnection, ExchangeProgress};
pub mod auth;
pub mod closure;
pub mod endpoint;
pub mod lease;
pub mod presence;
pub mod wire;

pub mod hello;
