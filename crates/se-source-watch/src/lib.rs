//! Read-only source-root custody and native filesystem watch primitives.
//!
//! Extracted from `se-proc` so directory-handle traversal and OS change
//! notification live in a focused OS crate without process-supervision coupling.

mod source_root;
mod workspace_write;

#[cfg(target_os = "linux")]
pub use source_root::NativeWatchWake;
pub use source_root::{
    NativeFileRevision, NativeRootDirectory, NativeRootFile, NativeSourceEntry, NativeSourceKind,
    NativeSourceRoot, NativeSourceScan, observe_file_revision,
};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use source_root::{
    NativeSourceWatch, NativeWatchAction, NativeWatchDirectory, NativeWatchEvent,
    NativeWatchEvents, NativeWatchRegistration,
};
pub use workspace_write::{WorkspaceWriteError, WorkspaceWriteRefusal};
