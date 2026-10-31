//! Native process contracts, protected files, owner observations and uninstall custody.
//!
//! See docs/design/30-process-ownership.md for normative semantics. The public
//! process traits remain declarations; NativeStateFiles supplies the real
//! protected staging/readback/publication adapter. Owner observations and the
//! Windows private uninstall handoff have concrete native implementations. Native
//! resource layouts are intentionally opaque; no handle is Clone or Default.

mod entropy;
pub use entropy::{NativeEntropyError, random_secret};
mod creation_owner;
mod error;
pub use creation_owner::{FileOwnerError, FileOwnerInitialization, initialize_file_creation_owner};
mod identity;
mod launch;
pub mod native_ipc;
mod owner_probe;
#[cfg(windows)]
mod uninstall;
#[cfg(windows)]
pub use uninstall::{
    NativeUninstallHandoff, NativeUninstallHelper, UninstallHandoffReceipt, UninstallImageWitness,
    UninstallNativeError, UninstallProcessIdentity, UninstallReady,
};
mod ownership;
mod state_files;
pub use state_files::{
    NativeStateFiles, ProtectedStateStaging, StateFileError, StateFileErrorCode,
};
#[cfg(windows)]
mod stdio;

pub use error::*;
pub use identity::*;
pub use launch::*;
pub use owner_probe::{
    AgentTreeBasis, AgentTreeMatch, NativeOwner, OwnerObservation, OwnerProbeError,
    observe_owner_self,
};
pub use ownership::*;
#[cfg(windows)]
pub use stdio::*;
