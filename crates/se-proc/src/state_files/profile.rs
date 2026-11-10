//! Custody for an existing provider-owned, current-user-only profile. The
//! provider creates its root; opening it never changes its security or layout.
use super::{NativeStateFiles, ProtectedStateStaging, Result, io_error, os};
use std::{fs::File, io, path::Path};

/// Private provider files have their own fixed native layout. On Windows only
/// the current user receives access; ordinary state files retain user + SYSTEM.
/// On Unix both layouts use the existing owner-only native protection.
pub struct NativeProfileFiles(NativeStateFiles);

impl NativeProfileFiles {
    pub fn open(root: &Path) -> Result<Self> {
        #[cfg(windows)]
        let directory = os::Directory::open_profile(root)?;
        #[cfg(unix)]
        let directory = os::Directory::open(root)?;
        Ok(Self(NativeStateFiles {
            root: root.into(),
            directory,
        }))
    }

    /// Missing is distinct from unreadable, unsafe or replaced. The returned
    /// file is read-only, regular, single-linked and private to the current user.
    pub fn readback(&self, path: &Path) -> Result<Option<File>> {
        self.0.readback(path)
    }

    pub fn create_staging(&self, directory: &Path) -> Result<ProtectedStateStaging> {
        self.0.create_staging(directory)
    }

    pub fn publish_no_replace(&self, staged: &Path, destination: &Path) -> Result<()> {
        self.0.publish_no_replace(staged, destination)
    }

    pub fn sha256(&self, path: &Path) -> Result<Option<[u8; 32]>> {
        if self.readback(path)?.is_none() {
            return Ok(None);
        }
        let pin = os::effects::Pin::open_profile(path)?.ok_or_else(|| {
            super::effects::changed("private profile file disappeared before hash", path)
        })?;
        let digest = super::effects::digest(pin.file(), path)?;
        pin.check()?;
        self.readback(path)?.ok_or_else(|| {
            super::effects::changed("private profile file disappeared after hash", path)
        })?;
        Ok(Some(digest))
    }

    /// Replace only the expected original bytes. Native comparison, backup and
    /// publication stay shared with owned-file replacement; private security is
    /// checked on the original, staging and independently reopened final file.
    pub fn replace(&self, path: &Path, expected: [u8; 32], bytes: &[u8]) -> Result<()> {
        self.0.check(path)?;
        // Check the entire profile-relative parent chain before acquiring the
        // mutation pin, which also rechecks the original private file security.
        let original = self.readback(path)?.ok_or_else(|| {
            io_error(
                "private profile file absent",
                path,
                io::ErrorKind::NotFound.into(),
            )
        })?;
        drop(original);
        let pin = os::effects::Pin::open_profile(path)?.ok_or_else(|| {
            io_error(
                "private profile file absent",
                path,
                io::ErrorKind::NotFound.into(),
            )
        })?;
        pin.replace(expected, bytes)?;
        self.readback(path)?.ok_or_else(|| {
            io_error(
                "replaced private file absent",
                path,
                io::ErrorKind::NotFound.into(),
            )
        })?;
        self.0.check(path)
    }
}
