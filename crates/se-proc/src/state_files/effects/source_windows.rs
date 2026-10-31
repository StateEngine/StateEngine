use super::{Parent, last, metadata, security, wide};
use crate::state_files::{
    Result,
    effects::{absent, changed},
};
use std::{
    fs::File,
    os::windows::io::FromRawHandle,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};

pub(in crate::state_files) struct ReadPin {
    path: PathBuf,
    physical: PathBuf,
    _parent: Parent,
    file: File,
    identity: super::Identity,
}
fn open(path: &Path) -> Result<File> {
    let name = wide(path)?;
    // SAFETY: terminated validated path; read-only rights, no-follow final
    // object and full sharing let the real provider keep appending/rotating.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(last("open retained read-only transcript", path));
    }
    // SAFETY: successful CreateFileW transferred one uniquely owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
impl ReadPin {
    pub(in crate::state_files) fn open(path: &Path) -> Result<Option<Self>> {
        let parent_path = path
            .parent()
            .ok_or_else(|| changed("transcript leaf missing", path))?;
        let name = path
            .file_name()
            .ok_or_else(|| changed("transcript leaf missing", path))?;
        let parent = match Parent::open_with_access(parent_path, false) {
            Ok(value) => value,
            Err(error) if absent(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let physical = parent.path.join(name);
        let file = match open(&physical) {
            Ok(file) => file,
            Err(error) if absent(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let identity = metadata(&file, path, false, false)?;
        security::verify_owner(&file, path)?;
        let pin = Self {
            path: path.into(),
            physical,
            _parent: parent,
            file,
            identity,
        };
        pin.check()?;
        Ok(Some(pin))
    }
    pub(in crate::state_files) fn file(&self) -> &File {
        &self.file
    }
    pub(in crate::state_files) fn identity(&self) -> Vec<u8> {
        self.identity
            .volume
            .to_le_bytes()
            .into_iter()
            .chain(self.identity.index)
            .collect()
    }
    pub(in crate::state_files) fn check(&self) -> Result<()> {
        let parent_path = self
            .path
            .parent()
            .ok_or_else(|| changed("transcript parent missing", &self.path))?;
        let parent = Parent::open_with_access(parent_path, false)?;
        if parent.identity != self._parent.identity {
            return Err(changed("transcript parent identity changed", &self.path));
        }
        let named = open(&self.physical)?;
        if metadata(&named, &self.path, false, false)? != self.identity
            || metadata(&self.file, &self.path, false, false)? != self.identity
        {
            return Err(changed(
                "transcript pathname no longer names the retained source",
                &self.path,
            ));
        }
        security::verify_owner(&named, &self.path)
    }
}
