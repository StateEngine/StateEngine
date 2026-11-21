use super::super::acl;
use super::{id, parent};
use crate::state_files::{
    Result,
    effects::{absent, changed},
    io_error,
    permissions::{PermissionKind, PermissionProtection, PermissionSnapshot},
    unsafe_path,
};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

pub(in crate::state_files) struct Pin {
    path: PathBuf,
    parent: File,
    name: CString,
    file: File,
    object: [u8; 32],
}
fn open_at(parent: &File, name: &CString, path: &Path) -> Result<File> {
    // SAFETY: held parent and literal NUL-terminated leaf; O_EVTONLY acquires
    // metadata custody without data access, execution or following the leaf.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io_error(
            "pin repair metadata without following links",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful openat transfers unique ownership of this descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn snapshot(file: &File, path: &Path) -> Result<PermissionSnapshot> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("read permission repair metadata", path, e))?;
    // SAFETY: immutable native current-user query, with no pointers.
    if meta.uid() != unsafe { libc::geteuid() }
        || (!meta.is_file() && !meta.is_dir())
        || (meta.is_file() && meta.nlink() != 1)
    {
        return Err(unsafe_path(
            "repair requires a current-user regular file/directory without hard links",
            path,
        ));
    }
    Ok(PermissionSnapshot {
        object: Sha256::digest([meta.dev().to_le_bytes(), meta.ino().to_le_bytes()].concat())
            .into(),
        owner: meta.uid().to_string(),
        kind: if meta.is_dir() {
            PermissionKind::Directory
        } else {
            PermissionKind::File
        },
        protection: PermissionProtection::MacOsAcl {
            mode: meta.mode() & 0o7777,
            group: meta.gid(),
            acl: acl::snapshot(file, path)?,
        },
    })
}
impl Pin {
    pub(in crate::state_files) fn open(path: &Path) -> Result<Option<Self>> {
        let (parent, name) = match parent(path) {
            Ok(value) => value,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let file = match open_at(&parent, &name, path) {
            Ok(value) => value,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let object = snapshot(&file, path)?.object;
        let pin = Self {
            path: path.into(),
            parent,
            name,
            file,
            object,
        };
        pin.check()?;
        Ok(Some(pin))
    }
    pub(in crate::state_files) fn snapshot(&self) -> Result<PermissionSnapshot> {
        snapshot(&self.file, &self.path)
    }
    pub(in crate::state_files) fn check(&self) -> Result<()> {
        let (current, _) = parent(&self.path)?;
        if id(&current, &self.path, true, false)? != id(&self.parent, &self.path, true, false)? {
            return Err(changed("permission repair parent changed", &self.path));
        }
        let named = open_at(&self.parent, &self.name, &self.path)?;
        if snapshot(&named, &self.path)?.object != self.object
            || self.snapshot()?.object != self.object
        {
            return Err(changed("permission repair path changed", &self.path));
        }
        Ok(())
    }
    pub(in crate::state_files) fn tighten(&self, expected: &PermissionSnapshot) -> Result<()> {
        if self.snapshot()? != *expected {
            return Err(changed(
                "permission or owner changed before native tightening",
                &self.path,
            ));
        }
        let PermissionProtection::MacOsAcl { mode, .. } = &expected.protection else {
            return Err(unsafe_path(
                "native Unix permission mode required",
                &self.path,
            ));
        };
        let target = if expected.kind == PermissionKind::Directory {
            0o700
        } else {
            0o600 | (*mode & 0o100)
        };
        if *mode & target != target {
            return Err(unsafe_path(
                "documented owner-only mode would add missing owner access; tighten-only repair refused",
                &self.path,
            ));
        }
        // Remove non-owner mode bits before clearing all ACL entries: even a
        // former deny ACE cannot expose group/other access when removed.
        if *mode != target {
            // SAFETY: retained event-only FD; target only removes existing bits.
            if unsafe { libc::fchmod(self.file.as_raw_fd(), target as libc::mode_t) } < 0 {
                return Err(io_error(
                    "tighten pinned Darwin mode",
                    &self.path,
                    io::Error::last_os_error(),
                ));
            }
        }
        acl::clear(&self.file, &self.path)?;
        Ok(())
    }
    pub(in crate::state_files) fn verify_private(&self) -> Result<()> {
        let snapshot = self.snapshot()?;
        let directory = snapshot.kind == PermissionKind::Directory;
        if !self.is_owner_only()? {
            return Err(changed(
                "exact documented owner-only mode was not retained",
                &self.path,
            ));
        }
        super::super::metadata(&self.file, &self.path, directory).map(|_| ())
    }
    pub(in crate::state_files) fn is_owner_only(&self) -> Result<bool> {
        let snapshot = self.snapshot()?;
        let PermissionProtection::MacOsAcl { mode, .. } = snapshot.protection else {
            return Err(unsafe_path(
                "Darwin permission snapshot required",
                &self.path,
            ));
        };
        let meta = self
            .file
            .metadata()
            .map_err(|e| io_error("read Darwin ACL owner", &self.path, e))?;
        Ok(
            (mode == 0o700 || (snapshot.kind == PermissionKind::File && mode == 0o600))
                && acl::is_owner_only(&self.file, meta.uid(), &self.path)?,
        )
    }
}
