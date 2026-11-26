//! Bounded, handle-relative atomic workspace file writes beneath a retained
//! `NativeSourceRoot`.
//!
//! Contract:
//! - Every directory traversal, directory creation, staging file, and atomic
//!   publication runs strictly relative to the retained root directory handle,
//!   never restarting from an absolute pathname.
//! - Symbolic links, reparse points, non-regular targets, mount crossings
//!   (Unix), and `.git` metadata (by spelling and by native object identity)
//!   are refused before any target mutation.
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
    /// The new file was atomically renamed into place, but post-publish
    /// durability sync or root verification failed; the new bytes may already
    /// be on disk.
    PublishedUncertain(String),
}

impl fmt::Display for WorkspaceWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforePublish(refusal) => write!(f, "{refusal}"),
            Self::PublishedUncertain(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for WorkspaceWriteError {}

impl NativeSourceRoot {
    /// Atomically write `bytes` to `path` beneath this retained workspace root
    /// without following links, crossing mounts, or modifying `.git` metadata.
    pub fn write_relative(&self, path: &str, bytes: &[u8]) -> Result<(), WorkspaceWriteError> {
        validate(path).map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::InvalidTarget(
                error.to_string(),
            ))
        })?;
        self.check().map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
        })?;
        os_write::write_relative(&self.directory, path, bytes, &|| self.check())?;
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
