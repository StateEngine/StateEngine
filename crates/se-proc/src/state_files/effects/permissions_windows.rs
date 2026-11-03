//! Metadata-only custody for a single file or directory. Neither data access nor
//! delete sharing is requested, and DACL repair never visits descendants.
use super::{Parent, metadata, security, wide};
use crate::state_files::{
    Result, StateFileErrorCode,
    effects::{absent, changed},
    io_error,
    permissions::{PermissionKind, PermissionProtection, PermissionSnapshot},
    unsafe_path,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::SE_FILE_OBJECT, *},
    Storage::FileSystem::*,
};

pub(in crate::state_files) struct Pin {
    path: PathBuf,
    parent: Parent,
    file: File,
    object: [u8; 32],
}
fn open_metadata(path: &Path, repair: bool) -> Result<File> {
    let name = wide(path)?;
    // SAFETY: retained terminated path, metadata/security rights only, no handle
    // inheritance, no leaf reparse traversal and no delete sharing for this pin.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | if repair { WRITE_DAC } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io_error(
            "pin permission repair metadata",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful CreateFileW transfers unique ownership of this handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn snapshot(file: &File, path: &Path) -> Result<PermissionSnapshot> {
    let info = crate::windows_native::file_information(file)
        .map_err(|e| io_error("read repair object kind", path, e))?;
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let identity = metadata(file, path, directory, false)?;
    let descriptor = crate::windows_native::acl::SecurityDescriptor::query(
        file.as_raw_handle(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )
    .map_err(|e| io_error("read repair object security", path, e))?;
    let owner = crate::windows_native::sid_text(descriptor.owner)
        .map_err(|e| io_error(e.operation, path, e.source))?;
    if owner != security::current_owner_sid(path)? {
        return Err(unsafe_path(
            "repair requires current OS user ownership",
            path,
        ));
    }
    let control = descriptor
        .control()
        .map_err(|e| io_error("read repair DACL control", path, e))?;
    let sddl = descriptor
        .sddl(DACL_SECURITY_INFORMATION)
        .map_err(|e| io_error("read repair DACL text", path, e))?;
    let mut hash = Sha256::new();
    hash.update(identity.volume.to_le_bytes());
    hash.update(identity.index);
    Ok(PermissionSnapshot {
        object: hash.finalize().into(),
        owner,
        kind: if directory {
            PermissionKind::Directory
        } else {
            PermissionKind::File
        },
        protection: PermissionProtection::WindowsDacl { sddl, control },
    })
}
impl Pin {
    pub(in crate::state_files) fn open(path: &Path) -> Result<Option<Self>> {
        wide(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| unsafe_path("repair requires a named path", path))?;
        let name = path
            .file_name()
            .ok_or_else(|| unsafe_path("repair requires a literal leaf", path))?;
        let parent = match Parent::open_for_permission_repair(parent_path) {
            Ok(value) => value,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let file = match open_metadata(&parent.path.join(name), false) {
            Ok(value) => value,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let object = snapshot(&file, path)?.object;
        let pin = Self {
            path: path.into(),
            parent,
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
        let parent_path = self
            .path
            .parent()
            .ok_or_else(|| unsafe_path("repair parent missing", &self.path))?;
        let current = Parent::open_for_permission_repair(parent_path)?;
        if current.identity != self.parent.identity {
            return Err(changed("permission repair parent changed", &self.path));
        }
        let name = self
            .path
            .file_name()
            .ok_or_else(|| unsafe_path("repair leaf missing", &self.path))?;
        let named = open_metadata(&current.path.join(name), false)?;
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
        // Diagnosis keeps read-only metadata handles. Request WRITE_DAC only
        // at the admitted effect, and compare that held object's full snapshot
        // before changing it; a newly named object never inherits the plan.
        let writable = open_metadata(&self.path, true)?;
        if snapshot(&writable, &self.path)? != *expected {
            return Err(changed(
                "named repair object changed before tightening",
                &self.path,
            ));
        }
        security::tighten_owner_only(
            &writable,
            &self.path,
            expected.kind == PermissionKind::Directory,
        )
    }
    pub(in crate::state_files) fn verify_private(&self) -> Result<()> {
        security::verify(
            &self.file,
            &self.path,
            self.snapshot()?.kind != PermissionKind::Directory,
        )
    }
    pub(in crate::state_files) fn is_owner_only(&self) -> Result<bool> {
        self.snapshot()?;
        match self.verify_private() {
            Ok(()) => Ok(true),
            Err(error) if error.code == StateFileErrorCode::LocationUnsafe => Ok(false),
            Err(error) => Err(error),
        }
    }
}
