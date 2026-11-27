//! Bounded, handle-relative atomic workspace file writes beneath a retained
//! `NativeSourceRoot`.
//!
//! Contract:
//! - Every directory traversal, directory creation, staging file, and exclusive
//!   creation runs strictly relative to retained native directory handles; on
//!   Windows, existing-file replacement uses `ReplaceFileW` on verified physical
//!   paths beneath pinned root and ancestor directory handles opened without
//!   `FILE_SHARE_DELETE`.
//! - Symbolic links, reparse points, non-regular targets, mount crossings
//!   (Unix), reserved DOS device names (Windows), and `.git` metadata (by
//!   spelling and by native object identity) are refused before mutation.
//! - Replacement carries an O(1) native identity/revision check (no unbounded
//!   read or hash of the replaced file); absent-destination writes publish
//!   exclusively so a concurrent creator's file is never overwritten.
//! - Failures before publication (`BeforePublish`) are distinct from post-
//!   publication durability or verification failures (`PublishedUncertain`).
use crate::source_root::{NativeSourceRoot, validate};
use std::{fmt, io};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as os_write;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os_write;

/// Why a workspace write was refused before the target file was modified.
#[derive(Debug)]
pub enum WorkspaceWriteRefusal {
    /// The workspace root was moved, removed, or could not be verified.
    RootUnverified(io::Error),
    /// The path is malformed, traverses a link/reparse point, targets a
    /// non-regular entry, crosses a mount boundary, or names `.git` metadata.
    InvalidTarget(String),
    /// An OS I/O error prevented creating or publishing the file before the
    /// target was replaced.
    Io(io::Error),
}

impl fmt::Display for WorkspaceWriteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootUnverified(error) => write!(f, "workspace root unverified: {error}"),
            Self::InvalidTarget(reason) => f.write_str(reason),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

/// Structured outcome error for [`NativeSourceRoot::write_relative`].
#[derive(Debug)]
pub enum WorkspaceWriteError {
    /// Refused or failed before the target path was modified.
    BeforePublish(WorkspaceWriteRefusal),
    /// A conflict occurred during publication, and the prior target state was
    /// positively confirmed restored with staging cleaned up.
    Restored(String),
    /// Publication or rollback outcome is unresolved: the target may have been
    /// modified, durability sync may have failed, or recovery siblings may remain.
    PublishedUncertain(String),
}

impl fmt::Display for WorkspaceWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforePublish(refusal) => write!(f, "{refusal}"),
            Self::Restored(reason) => f.write_str(reason),
            Self::PublishedUncertain(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for WorkspaceWriteError {}

impl NativeSourceRoot {
    /// Write `bytes` to `path` beneath this retained workspace root without
    /// following links, crossing mounts, or modifying `.git` metadata.
    ///
    /// Existing-file replacement uses an atomic swap without an absence window
    /// on filesystems that support `renameat2(RENAME_EXCHANGE)` /
    /// `renameatx_np(RENAME_SWAP)` (and `ReplaceFileW` on Windows). On Unix
    /// mounts lacking atomic swap (such as WSL2 `/mnt/c`, VirtioFS, FUSE,
    /// NFS/SMB, or non-APFS macOS volumes), replacement falls back to a
    /// non-overwriting backup-rename plus exclusive `linkat` sequence that has
    /// a brief absence window while preserving concurrent edits; mounts where
    /// hard links are also unsupported refuse before modifying the target.
    pub fn write_relative(&self, path: &str, bytes: &[u8]) -> Result<(), WorkspaceWriteError> {
        validate(path).map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::InvalidTarget(
                error.to_string(),
            ))
        })?;
        self.check().map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
        })?;
        os_write::write_relative(&self.directory, &self.path, path, bytes, &|| self.check())?;
        self.check().map_err(|error| {
            WorkspaceWriteError::PublishedUncertain(format!(
                "workspace root could not be verified after publication: {error}"
            ))
        })
    }
}

pub(super) fn stage_name() -> Result<String, WorkspaceWriteError> {
    let mut nonce = [0u8; 16];
    se_state_files::fill_entropy(&mut nonce).map_err(|error| {
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(io::Error::other(
            error.to_string(),
        )))
    })?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(".se-write-".len() + 32);
    name.push_str(".se-write-");
    for byte in nonce {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(name)
}
