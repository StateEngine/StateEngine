//! Shared local IPC client/listener and host contracts.
//! Runtime/provider admission and dispatch are supplied by their host adapters.
//! Canonical declarations for docs/design/40-host-runtime-and-harnesses.md.
//! The separately owned permissive linked API remains section 10's contract.
#[cfg(test)]
extern crate self as se_host;
pub mod client;
mod harness;
mod ipc;
mod model;
mod runtime;
mod session;
pub mod state_files;
pub use harness::*;
pub use ipc::*;
pub use model::*;
pub use runtime::*;
pub use session::*;
