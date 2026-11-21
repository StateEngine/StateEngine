//! Shared local IPC client/listener and host contracts.
//! Runtime/provider admission and dispatch are supplied by their host adapters.
#[cfg(test)]
extern crate self as se_host;
#[cfg(feature = "listener")]
pub use se_harness::acp;
#[cfg(all(test, feature = "listener"))]
#[path = "../tests/support/acp_session_independent.rs"]
mod acp_session_independent;
#[cfg(all(test, feature = "listener"))]
#[path = "../tests/support/acp_transport_independent.rs"]
mod acp_transport_independent;
pub mod adoption;
#[cfg(feature = "runtime")]
mod agent_observation;
#[cfg(feature = "channels")]
pub mod channels;
#[cfg(feature = "listener")]
pub(crate) use se_harness::child_io;
pub mod client;
pub mod remote;
#[cfg(feature = "remote")]
mod return_mail;
#[cfg(feature = "remote")]
mod ssh_transport;
#[cfg(test)]
#[path = "../../test-support/directory.rs"]
mod test_directory;
#[cfg(feature = "runtime")]
pub use agent_observation::{
    AgentObservation, AgentObservationPlan, observe_agent, prepare_agent_observation,
};
pub(crate) use se_harness::harness;
pub mod harness_setup;
mod owner_inventory;
pub use owner_inventory::decode_owner_inventory;
#[cfg(feature = "runtime")]
mod launch_proofs;
#[cfg(feature = "runtime")]
pub use launch_proofs::{PreparedFirstRequests, PreparedRequestProofs, VerifiedPreparedRequest};
#[cfg(feature = "listener")]
mod http;
#[cfg(feature = "listener")]
pub use http::HttpListener;
mod connection_hello;
mod ipc;
mod launch_sign_in;
pub use launch_sign_in::SignIn;
#[cfg(feature = "listener")]
mod mcp_lease;
pub use mcp::{McpBackend, McpReply};
pub mod mcp {
    pub use se_mcp::{McpBackend, McpPrincipal, McpReply, dispatch};
}
pub(crate) use se_harness::model;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod process;
#[cfg(feature = "listener")]
pub(crate) use se_harness::process_io;
#[cfg(feature = "listener")]
pub mod provider_mcp;
mod runtime;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub use process::launch_util::resolve_provider as resolve_provider_executable;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub use process::{
    ProcessConfiguration, ProcessDrain, ProcessOptions, Reconciliation, mail_wake_interval,
};
#[cfg(all(unix, feature = "listener"))]
pub use process_io::UnixProviderIo;
#[cfg(all(windows, feature = "listener"))]
pub use process_io::WindowsProviderIo;
pub use se_atlas_cold::atlas_cache;
pub use se_atlas_cold::atlas_source;
#[cfg(feature = "listener")]
use se_atlas_host::atlas_continuity;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
pub use se_atlas_host::atlas_renewal;
pub use se_atlas_host::{atlas_cold, atlas_hooks, atlas_queries, atlas_records, atlas_runtime};
pub(crate) use se_harness::session;
#[cfg(feature = "listener")]
pub(crate) use se_harness::startup_timing;
pub mod state_files;
pub use harness::*;
pub use ipc::*;
pub use model::*;
pub use runtime::*;
pub use session::*;

#[cfg(feature = "secode")]
pub use se_harness::linked;

#[cfg(all(test, feature = "listener"))]
#[path = "../tests/support/acp_correction_independent.rs"]
mod acp_correction_independent;
