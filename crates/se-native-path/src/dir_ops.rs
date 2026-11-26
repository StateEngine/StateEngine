//! Handle-anchored, non-following directory traversal and mutation primitives.
//!
//! All directory inspection, entry enumeration, identity checks, readonly
//! attribute clearing (Windows only), and file/directory deletion operate on
//! retained OS directory handles (`openat`/`fdopendir`/`statx`/`unlinkat` on
//! Unix; `NtCreateFile`/`FileIdInfo`/`FileFullDirectoryInfo`/`FileBasicInfo`/
//! `FileDispositionInfo` on Windows) rather than re-resolving paths by name.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::{
    ffi::{OsStr, OsString},
    io,
    path::Path,
};

#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
use windows as imp;

/// Stable filesystem identity queried directly from a retained OS handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeId {
    #[cfg(unix)]
    pub dev: u64,
    #[cfg(unix)]
    pub ino: u64,
    /// Linux `statx` mount ID (`STATX_MNT_ID`) when supported by the kernel.
    #[cfg(unix)]
    pub mount_id: Option<u64>,
    #[cfg(windows)]
    pub volume: u64,
    #[cfg(windows)]
    pub index: [u8; 16],
}

impl NodeId {
    /// Returns true if `other` lives on a different device or Linux mount ID.
    pub fn crosses_mount_from(self, root: Self) -> bool {
        #[cfg(unix)]
        {
            if self.dev != root.dev {
                return true;
            }
            if let (Some(a), Some(b)) = (self.mount_id, root.mount_id)
                && a != b
            {
                return true;
            }
            false
        }
        #[cfg(windows)]
        {
            self.volume != root.volume
        }
    }
}

/// Non-following entry classification from a handle-relative query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildKind {
    File,
    Dir,
    Link(&'static str),
    Other,
}

/// Metadata for one child entry queried relative to a held [`DirHandle`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildInfo {
    pub kind: ChildKind,
    pub id: NodeId,
    /// True on Linux when `statx` reports `STATX_ATTR_MOUNT_ROOT`.
    pub is_mount_root: bool,
}

/// Error opening a directory without following links/reparse points.
#[derive(Debug)]
pub enum DirOpError {
    NotFound,
    Link(&'static str),
    NotDir,
    Io(io::Error),
}

/// Error deleting a child entry relative to a held [`DirHandle`].
#[derive(Debug)]
pub enum DeleteChildError {
    Link(&'static str),
    IdentityMismatch,
    /// Windows-only: clearing `FILE_ATTRIBUTE_READONLY` on the verified handle failed.
    ClearReadonlyFailed(io::Error),
    Io(io::Error),
}

/// A retained, non-following OS directory handle.
pub struct DirHandle(imp::DirHandle);

impl DirHandle {
    /// Open `path` as a real directory without following a final symlink or
    /// Windows reparse point.
    pub fn open_root(path: &Path) -> Result<Self, DirOpError> {
        imp::DirHandle::open_root(path).map(Self)
    }

    /// Open a direct child directory by literal name relative to `self` without
    /// following symlinks or Windows reparse points.
    pub fn open_child_dir(&self, name: &OsStr) -> Result<Self, DirOpError> {
        self.0.open_child_dir(name).map(Self)
    }

    /// Query stable identity and mount-root status directly from this handle.
    pub fn stat_self(&self) -> io::Result<(NodeId, bool)> {
        self.0.stat_self()
    }

    /// Enumerate direct child entry names (excluding `.` and `..`) from this
    /// retained handle without re-resolving any path.
    pub fn read_entries(&self) -> io::Result<Vec<OsString>> {
        self.0.read_entries()
    }

    /// Inspect one direct child by literal name relative to `self` without
    /// following symlinks or reparse points.
    pub fn inspect_child(&self, name: &OsStr) -> Result<ChildInfo, DirOpError> {
        self.0.inspect_child(name)
    }

    /// Read a direct regular child file by literal name relative to `self`
    /// without following symlinks or reparse points, capped at `max_bytes`.
    pub fn read_child_file(&self, name: &OsStr, max_bytes: usize) -> Result<Vec<u8>, DirOpError> {
        self.0.read_child_file(name, max_bytes)
    }

    /// Exclusively create a direct regular child file by literal name relative
    /// to `self` without following symlinks or reparse points, writing `bytes`.
    pub fn create_child_file_exclusive(&self, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
        self.0.create_child_file_exclusive(name, bytes)
    }

    /// Unlink a direct non-directory child relative to `self`.
    /// Verifies non-link status and `expected_id` (when provided) before
    /// unlinking. On Windows, clears `FILE_ATTRIBUTE_READONLY` on the same
    /// verified handle and surfaces any attribute-clear failure distinctly.
    pub fn unlink_child_file(
        &self,
        name: &OsStr,
        expected_id: Option<NodeId>,
    ) -> Result<(), DeleteChildError> {
        self.0.unlink_child_file(name, expected_id)
    }

    /// Remove a direct empty child directory relative to `self`.
    /// Verifies non-link status and `expected_id` (when provided) before
    /// removing. On Windows, clears `FILE_ATTRIBUTE_READONLY` on the same
    /// verified handle and surfaces any attribute-clear failure distinctly.
    pub fn remove_child_dir(
        &self,
        name: &OsStr,
        expected_id: Option<NodeId>,
    ) -> Result<(), DeleteChildError> {
        self.0.remove_child_dir(name, expected_id)
    }

    /// On Unix, check whether the current process has write+search access on
    /// this directory handle (`faccessat`). Always returns `Ok(true)` on Windows.
    pub fn can_modify_entries(&self) -> io::Result<bool> {
        self.0.can_modify_entries()
    }
}
