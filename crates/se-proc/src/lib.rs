//! Native process contracts, protected files, owner observations and uninstall custody.
//!
//! See docs/design/30-process-ownership.md for normative semantics. The public
//! process traits remain declarations; NativeStateFiles supplies the real
//! protected staging/readback/publication adapter. Owner observations and the
//! Windows private uninstall handoff have concrete native implementations. Native
//! resource layouts are intentionally opaque; no handle is Clone or Default.

mod checkpoint;
pub use checkpoint::{
    Checkpoint, CheckpointError, CheckpointKind, CheckpointPrincipal, CheckpointSource,
    HistoricalCheckpoint, RootPublication, decode_checkpoint, encode_checkpoint,
};
mod error;
mod identity;
mod launch;
pub mod native_ipc;
mod owner_probe;
#[cfg(windows)]
mod uninstall;
#[cfg(windows)]
pub use uninstall::{
    HelperCleanupOutcome, NativeUninstallHandoff, NativeUninstallHelper, UninstallHandoffReceipt,
    UninstallHelperCleanup, UninstallImageWitness, UninstallNativeError, UninstallProcessIdentity,
    UninstallReady,
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
    AgentTreeBasis, AgentTreeMatch, AncestryBound, NativeOwner, OwnerObservation, OwnerProbeError,
    OwnerTarget, OwnerTreeObservation, observe_owner, observe_owner_self,
};
pub use ownership::*;
#[cfg(windows)]
pub use stdio::*;

#[cfg(any(target_os = "linux", windows))]
mod bootstrap;
#[cfg(any(target_os = "linux", windows))]
pub use bootstrap::{
    NativeRuntimeIdentity, RuntimeAdmission, RuntimeBootstrap, current_process_identity,
    current_runtime_identity,
};
#[cfg(any(target_os = "linux", windows))]
mod platform;
#[cfg(any(target_os = "linux", windows))]
mod runtime;
#[cfg(any(target_os = "linux", windows))]
mod support;
#[cfg(windows)]
mod windows_native;
#[cfg(any(target_os = "linux", windows))]
pub use runtime::read_process;
mod creation_owner;
pub use creation_owner::{FileOwnerError, FileOwnerInitialization, initialize_file_creation_owner};

pub use state_files::effects::{
    CreatedDirectoryCleanup, DirectoryRemoval, NativeDirectoryCreation, NativeInstallationClaim,
    OwnedFile, remove_empty_directory, scan_recovery, scan_temporary,
};
pub use state_files::source::{NativeSourcePin, SourceChunk};
#[cfg(windows)]
pub use state_files::user_path::{
    NativeUserPath, PathKind, PathObservation, PathUpdateError, PathUpdatePhase, PathWriteWitness,
};

mod entropy;
pub use entropy::{NativeEntropyError, random_secret};

mod birth_time;
pub use birth_time::{ProcessBirthTime, observe_process_birth};
