//! Provider harness adapters, ACP transport, child process I/O, and shared harness contracts.
#[cfg(feature = "listener")]
pub mod acp;
pub mod acquisition;
#[cfg(feature = "listener")]
pub mod child_io;
#[cfg(feature = "listener")]
mod codex_endpoint;
pub mod deadline;
pub mod harness;
pub mod json_wire;
#[cfg(feature = "secode")]
pub mod linked;
pub mod model;
pub mod network_env;
#[cfg(feature = "runtime")]
pub mod pool;
pub mod ports;
#[cfg(feature = "listener")]
pub mod process_io;
pub mod session;
pub mod sign_in;
#[cfg(feature = "listener")]
pub mod startup_timing;
#[cfg(test)]
#[path = "../../test-support/directory.rs"]
mod test_directory;
pub mod version;

pub use deadline::{
    CALL_TIMEOUT, ClientOptions, Deadline, HELLO_TIMEOUT, IDLE_TIMEOUT, WRITE_TIMEOUT,
};
pub use harness::*;
pub use model::*;
#[cfg(feature = "runtime")]
pub use pool::{BlockingClass, BlockingPool};
pub use ports::{AtlasHookConfigFn, BellRegistry, LivePublisher, LiveTurnRole};
#[cfg(all(unix, feature = "listener"))]
pub use process_io::UnixProviderIo;
#[cfg(all(windows, feature = "listener"))]
pub use process_io::WindowsProviderIo;
#[cfg(feature = "listener")]
pub use se_local_socket::{
    PeerProcess as LocalSocketPeer, probe_peer_identity as probe_local_socket_peer,
};
pub use session::*;
pub use sign_in::SignIn;
