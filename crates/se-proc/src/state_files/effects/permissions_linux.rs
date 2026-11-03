use super::{id, parent};
use crate::state_files::{
    Result, StateFileErrorCode,
    effects::{absent, changed},
    failure, io_error,
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
    // SAFETY: held parent and literal NUL-terminated leaf; O_PATH acquires
    // metadata custody without data access, execution or following the leaf.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
        protection: PermissionProtection::UnixMode {
            mode: meta.mode() & 0o7777,
            group: meta.gid(),
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
        let PermissionProtection::UnixMode { mode, .. } = expected.protection else {
            return Err(unsafe_path(
                "native Unix permission mode required",
                &self.path,
            ));
        };
        // SAFETY: retained O_PATH descriptor, empty literal pathname and a mode
        // that removes all special/group/other bits without adding owner rights.
        let result = unsafe {
            libc::syscall(
                libc::SYS_fchmodat2,
                self.file.as_raw_fd(),
                c"".as_ptr(),
                mode & 0o700,
                libc::AT_EMPTY_PATH,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
            ) {
                return Err(failure(
                    StateFileErrorCode::Unsupported,
                    "metadata-only repair requires fchmodat2 AT_EMPTY_PATH",
                    &self.path,
                ));
            }
            return Err(io_error("tighten pinned mode", &self.path, error));
        }
        Ok(())
    }
    pub(in crate::state_files) fn verify_private(&self) -> Result<()> {
        let directory = self.snapshot()?.kind == PermissionKind::Directory;
        super::super::metadata(&self.file, &self.path, directory).map(|_| ())
    }
}
