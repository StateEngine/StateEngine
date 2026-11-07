//! Native process contracts, protected files, owner observations and uninstall custody.
//!
//! See docs/design/30-process-ownership.md for normative semantics. The public
//! process runtime and Windows provider streams share one native custody arena.
//! NativeStateFiles supplies protected staging/readback/publication. Owner observations and the
//! Windows system uninstall carrier have concrete native implementations. Native
//! resource layouts are intentionally opaque; no handle is Clone or Default.

#[cfg(windows)]
mod windows_directory;
#[cfg(windows)]
pub use windows_directory::windows_directory;
#[cfg(windows)]
mod windows_package;
#[cfg(windows)]
pub use windows_package::process_has_package_identity;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod allocator;
pub mod atlas_git;
pub mod atlas_worker;
mod canonical_path;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub use allocator::reclaim_unused_allocator_pages;
mod checkpoint;
pub use canonical_path::canonicalize_path;
pub use checkpoint::{
    Checkpoint, CheckpointError, CheckpointKind, CheckpointPrincipal, CheckpointSource,
    HistoricalCheckpoint, RootPublication, decode_checkpoint, encode_checkpoint,
};
mod error;
mod identity;
mod launch;
mod native_error;
pub mod native_ipc;
mod owner_probe;
#[cfg(windows)]
mod uninstall;
#[cfg(windows)]
pub use uninstall::{
    HelperCleanupOutcome, NativeUninstallCarrier, UninstallHelperCleanup, UninstallNativeError,
};
mod ownership;
#[cfg(any(target_os = "linux", windows))]
mod process_command;
#[cfg(any(target_os = "linux", windows))]
pub use process_command::read_process_command;
#[cfg(target_os = "linux")]
mod process_descendants;
#[cfg(target_os = "linux")]
pub use process_descendants::read_process_descendants;
mod source_root;
#[cfg(target_os = "linux")]
pub use source_root::{
    NativeSourceWatch, NativeWatchAction, NativeWatchDirectory, NativeWatchEvent,
    NativeWatchEvents, NativeWatchRegistration,
};
mod state_files;
pub use source_root::{
    NativeFileRevision, NativeRootDirectory, NativeRootFile, NativeSourceEntry, NativeSourceKind,
    NativeSourceRoot, observe_file_revision,
};
pub use state_files::{
    NativeStateFiles, PermissionKind, PermissionProtection, PermissionRepairPin,
    PermissionRepairWitness, PermissionSnapshot, ProtectedStateStaging, StateFileError,
    StateFileErrorCode,
};
#[cfg(windows)]
mod stdio;

pub use error::*;
pub use identity::*;
pub use launch::*;
#[cfg(target_os = "macos")]
pub use owner_probe::observe_boot_id;
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
    NativeRuntimeIdentity, RuntimeAdmission, RuntimeBootstrap, RuntimeStartupStderr,
    current_process_identity, current_runtime_identity,
};
#[cfg(target_os = "linux")]
mod linux_native;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod platform;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod runtime;
mod support;
#[cfg(windows)]
mod windows_native;
#[cfg(windows)]
pub use platform::observe_prepared_scope_exit;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use runtime::{read_process, read_process_until};
#[cfg(target_os = "macos")]
mod macos_process;
#[cfg(target_os = "macos")]
pub use platform::process_attach_entry;
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
pub use entropy::{NativeEntropyError, fill_entropy, random_secret};

mod birth_time;
pub use birth_time::{ProcessBirthTime, observe_process_birth};

#[cfg(all(test, windows))]
#[path = "../tests/support/windows_policy_fixture.rs"]
mod windows_policy_fixture;

mod session_pin;
pub use session_pin::{
    SessionPinRemoval, publish_session_pin, read_session_pin, remove_session_pin, session_launch_id,
};

#[cfg(target_os = "linux")]
mod self_resources;
#[cfg(target_os = "linux")]
pub use self_resources::{SelfResources, observe_self_resources};

#[cfg(windows)]
mod parent_image;
#[cfg(windows)]
pub use parent_image::parent_process_image;

pub mod atlas_sql;
