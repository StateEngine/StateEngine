//! Owner-only local IPC endpoints, native peer observations, and OS process-query helpers.
//!
//! Extracted from `se-proc` so local socket/named-pipe transport and peer-identity
//! proofs live in a focused OS crate without process-supervision coupling.

mod canonical_path;
#[cfg(target_os = "linux")]
pub mod linux_native;
#[cfg(windows)]
mod native_file_revision;
pub mod native_ipc;
#[cfg(windows)]
pub mod windows_process;

pub use canonical_path::canonicalize_path;
pub use native_ipc::*;
