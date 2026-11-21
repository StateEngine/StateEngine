//! Protected native state files, file ownership/identity custody, and OS entropy.
//!
//! Extracted from `se-proc` so filesystem security and staging primitives live
//! in a focused OS crate without process-supervision or IPC coupling.

#[cfg(unix)]
pub mod advisory_lock;
mod creation_owner;
mod entropy;
mod file_identity;
mod file_revision;
pub mod native_error;
pub mod state_files;
#[cfg(windows)]
pub mod windows_attributes;

pub use creation_owner::{FileOwnerError, FileOwnerInitialization, initialize_file_creation_owner};
pub use entropy::{NativeEntropyError, fill_entropy, random_secret};
pub use file_identity::NativeFileIdentity;
pub use file_revision::{NativeFileRevision, observe_file_revision, observe_file_revision_for};
pub use state_files::effects::{
    CreatedDirectoryCleanup, DirectoryRemoval, NativeDirectoryCreation, NativeInstallationClaim,
    OwnedFile, installation_claim_path, remove_empty_directory, scan_recovery, scan_temporary,
};
pub use state_files::source::{NativeSourcePin, SourceChunk};
#[cfg(windows)]
pub use state_files::user_path::{
    NativeUserPath, PathKind, PathObservation, PathUpdateError, PathUpdatePhase, PathWriteWitness,
};
pub use state_files::{
    NativeMetadataPin, NativeProfileFiles, NativeStateFiles, PermissionKind, PermissionProtection,
    PermissionRepairPin, PermissionRepairWitness, PermissionSnapshot, ProtectedStateStaging,
    StateFileError, StateFileErrorCode,
};
