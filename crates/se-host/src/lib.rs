//! Shared local IPC client/listener and host contracts.
//! Runtime/provider admission and dispatch are supplied by their host adapters.
//! Canonical declarations for docs/design/40-host-runtime-and-harnesses.md.
//! The separately owned permissive linked API remains section 10's contract.
#[cfg(test)]
extern crate self as se_host;
#[cfg(feature = "runtime")]
mod agent_observation;
pub mod client;
#[cfg(feature = "runtime")]
pub use agent_observation::{
    AgentObservation, AgentObservationPlan, observe_agent, prepare_agent_observation,
};
mod harness;
#[cfg(feature = "runtime")]
mod launch_proofs;
#[cfg(feature = "runtime")]
pub use launch_proofs::{PreparedFirstRequests, PreparedRequestProofs, VerifiedPreparedRequest};
#[cfg(feature = "listener")]
mod http;
#[cfg(feature = "listener")]
pub use http::HttpListener;
mod ipc;
pub mod mcp;
pub use mcp::{McpBackend, McpReply};
mod model;
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
mod process;
mod runtime;
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub use process::{ProcessConfiguration, ProcessDrain, ProcessOptions, Reconciliation};
pub mod atlas_source;
mod session;
pub mod state_files;
pub use harness::*;
pub use ipc::*;
pub use model::*;
pub use runtime::*;
pub use session::*;

#[cfg(feature = "secode")]
pub mod linked;
