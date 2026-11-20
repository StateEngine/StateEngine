//! Shared local IPC client/listener and host contracts.
//! Runtime/provider admission and dispatch are supplied by their host adapters.
#[cfg(test)]
extern crate self as se_host;
#[cfg(feature = "listener")]
pub mod acp;
#[cfg(all(test, feature = "listener"))]
#[path = "../tests/support/acp_session_independent.rs"]
mod acp_session_independent;
#[cfg(all(test, feature = "listener"))]
#[path = "../tests/support/acp_transport_independent.rs"]
mod acp_transport_independent;
pub mod adoption;
#[cfg(feature = "runtime")]
mod agent_observation;
pub mod channels;
#[cfg(feature = "listener")]
mod child_io;
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
mod harness;
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
mod ipc;
pub use mcp::{McpBackend, McpReply};
pub use se_mcp as mcp;
mod model;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod process;
#[cfg(feature = "listener")]
mod process_io;
mod runtime;
#[cfg(feature = "listener")]
mod startup_timing;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub use process::launch_util::resolve_provider as resolve_provider_executable;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub use process::{ProcessConfiguration, ProcessDrain, ProcessOptions, Reconciliation};
#[cfg(all(unix, feature = "listener"))]
pub use process_io::UnixProviderIo;
#[cfg(all(windows, feature = "listener"))]
pub use process_io::WindowsProviderIo;
pub mod atlas_cache;
pub mod atlas_cold;
#[cfg(feature = "listener")]
mod atlas_continuity;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
mod atlas_git_watch;
pub mod atlas_hooks;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
mod atlas_ignore;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod atlas_parse;
pub mod atlas_queries;
pub mod atlas_records;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
pub mod atlas_renewal;
pub mod atlas_runtime;
pub mod atlas_source;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
mod atlas_watch_error;
mod session;
pub mod state_files;
pub use harness::*;
pub use ipc::*;
pub use model::*;
pub use runtime::*;
pub use session::*;

#[cfg(feature = "secode")]
pub mod linked;

#[cfg(all(test, feature = "listener"))]
#[path = "../tests/support/acp_correction_independent.rs"]
mod acp_correction_independent;
