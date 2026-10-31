use super::*;
use std::{
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Component,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Cryptography::*, *},
    Storage::FileSystem::*,
};

mod security;
use security::descriptor;
fn wide(path: &Path) -> Result<Vec<u16>> {
    let value: Vec<_> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) || value.len() > 32767 {
        return Err(unsafe_path(
            "bounded native path without NUL required",
            path,
        ));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
fn last(operation: &'static str, path: &Path) -> StateFileError {
    io_error(operation, path, io::Error::last_os_error())
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    volume: u32,
    index: u64,
}
fn metadata(file: &File, path: &Path, directory: bool, check_security: bool) -> Result<Identity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(last("read pinned native file identity", path));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
    {
        return Err(unsafe_path(
            "native regular file/directory without reparse point required",
            path,
        ));
    }
    if !directory && info.nNumberOfLinks != 1 {
        return Err(unsafe_path("state file has external hard links", path));
    }
    if check_security {
        security::verify(file, path)?;
    }
    Ok(Identity {
        volume: info.dwVolumeSerialNumber,
        index: (info.nFileIndexHigh as u64) << 32 | info.nFileIndexLow as u64,
    })
}
fn open(path: &Path, directory: bool, create: bool) -> Result<File> {
    let data = wide(path)?;
    let descriptor = if create {
        Some(descriptor(path)?)
    } else {
        None
    };
    let attributes = descriptor.as_ref().map(|s| SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: s.0,
        bInheritHandle: 0,
    });
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
    // Directory pins deny delete sharing for their entire lifetime. File pins
    // permit our own no-replace rename while retaining the original object.
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | if directory { 0 } else { FILE_SHARE_DELETE };
    let raw = unsafe {
        CreateFileW(
            data.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            share,
            attributes.as_ref().map_or(ptr::null(), |a| a as *const _),
            if create { CREATE_NEW } else { OPEN_EXISTING },
            flags,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(last("open protected native file", path));
    }
    // SAFETY: successful native allocation transfers exactly one owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn walk(path: &Path, create: bool, private_from: Option<&Path>) -> Result<File> {
    if !path.is_absolute() {
        return Err(unsafe_path("absolute state directory required", path));
    }
    let mut prefix = PathBuf::new();
    let mut last_file = None;
    for component in path.components() {
        match component {
            Component::Prefix(p) => {
                prefix.push(p.as_os_str());
                continue;
            }
            Component::RootDir => prefix.push(component.as_os_str()),
            Component::Normal(n) => {
                let units: Vec<_> = n.encode_wide().collect();
                if units.contains(&(b':' as u16))
                    || units
                        .last()
                        .is_some_and(|u| *u == b'.' as u16 || *u == b' ' as u16)
                {
                    return Err(unsafe_path("ambiguous native directory component", path));
                }
                prefix.push(n);
                if create {
                    let parent_path = prefix
                        .parent()
                        .ok_or_else(|| unsafe_path("directory parent missing", &prefix))?;
                    let sd = descriptor(&prefix)?;
                    let sa = SECURITY_ATTRIBUTES {
                        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                        lpSecurityDescriptor: sd.0,
                        bInheritHandle: 0,
                    };
                    let created = unsafe { CreateDirectoryW(wide(&prefix)?.as_ptr(), &sa) };
                    if created == 0 {
                        if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
                            return Err(last("create protected directory", &prefix));
                        }
                    } else {
                        let parent = open(parent_path, true, false)?;
                        metadata(&parent, parent_path, true, false)?;
                        parent
                            .sync_all()
                            .map_err(|e| io_error("flush new directory parent", parent_path, e))?;
                    }
                }
            }
            _ => return Err(unsafe_path("normalized state directory required", path)),
        }
        // Ancestors need query/traverse only. The final private root and every
        // descendant receive full protection checks, never an inherited-DACL guess.
        let file = if prefix == path || private_from.is_some_and(|root| prefix.starts_with(root)) {
            let file = open(&prefix, true, false)?;
            metadata(&file, &prefix, true, true)?;
            file
        } else {
            let raw = unsafe {
                CreateFileW(
                    wide(&prefix)?.as_ptr(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    ptr::null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE || raw.is_null() {
                return Err(last("open native ancestor", &prefix));
            }
            let file = unsafe { File::from_raw_handle(raw) };
            metadata(&file, &prefix, true, false)?;
            file
        };
        last_file = Some(file);
    }
    last_file.ok_or_else(|| unsafe_path("state directory missing", path))
}
pub(super) fn create_directories(path: &Path) -> Result<()> {
    let file = walk(path, true, None)?;
    file.sync_all()
        .map_err(|e| io_error("flush created state directory", path, e))
}
pub(super) struct Directory {
    file: File,
    identity: Identity,
}
impl Directory {
    pub fn open(path: &Path) -> Result<Self> {
        let file = walk(path, false, None)?;
        let identity = metadata(&file, path, true, true)?;
        Ok(Self { file, identity })
    }
    pub fn check_name(&self, path: &Path) -> Result<()> {
        let found = Self::open(path)?;
        if found.identity != self.identity {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "held state directory was replaced",
                path,
            ));
        }
        metadata(&self.file, path, true, true)?;
        Ok(())
    }
    fn parent(&self, path: &Path, root: &Path) -> Result<File> {
        walk(
            path.parent()
                .ok_or_else(|| unsafe_path("file parent missing", path))?,
            false,
            Some(root),
        )
    }
    pub fn create_staging(&self, directory: &Path, root: &Path) -> Result<ProtectedStateStaging> {
        let parent = walk(directory, false, Some(root))?;
        for _ in 0..8 {
            let mut random = [0; 16];
            // SAFETY: owned fixed-size buffer; system-preferred CSPRNG requires
            // no algorithm handle or ambient provider configuration.
            let status = unsafe {
                BCryptGenRandom(
                    ptr::null_mut(),
                    random.as_mut_ptr(),
                    random.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status < 0 {
                return Err(io_error(
                    "native staging entropy",
                    directory,
                    io::Error::other(format!("BCryptGenRandom NTSTATUS {status}")),
                ));
            }
            let path = directory.join(format!(
                ".se-stage-{}",
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            let file = match open(&path, false, true) {
                Ok(file) => file,
                Err(e) if e.code == StateFileErrorCode::AlreadyExists => continue,
                Err(e) => return Err(e),
            };
            metadata(&file, &path, false, true)?;
            parent
                .sync_all()
                .map_err(|e| io_error("flush staging parent", directory, e))?;
            return Ok(ProtectedStateStaging { path, file });
        }
        Err(failure(
            StateFileErrorCode::AlreadyExists,
            "native staging name collisions",
            directory,
        ))
    }
    pub fn readback(&self, path: &Path, root: &Path) -> Result<Option<File>> {
        let _parent = match self.parent(path, root) {
            Ok(v) => v,
            Err(e)
                if e.source
                    .as_ref()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let file = match open(path, false, false) {
            Ok(file) => file,
            Err(e)
                if e.source
                    .as_ref()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        metadata(&file, path, false, true)?;
        Ok(Some(file))
    }
    pub fn publish(&self, staged: &Path, destination: &Path, root: &Path) -> Result<()> {
        let source = self.readback(staged, root)?.ok_or_else(|| {
            io_error(
                "staging file absent",
                staged,
                io::Error::from(io::ErrorKind::NotFound),
            )
        })?;
        let before = metadata(&source, staged, false, true)?;
        source
            .sync_all()
            .map_err(|e| io_error("flush staged file", staged, e))?;
        let from = self.parent(staged, root)?;
        let to = self.parent(destination, root)?;
        // No REPLACE_EXISTING or COPY_ALLOWED: an existing destination is never
        // overwritten, and a different volume cannot turn rename into a copy.
        if unsafe {
            MoveFileExW(
                wide(staged)?.as_ptr(),
                wide(destination)?.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(last("no-replace write-through publication", destination));
        }
        source
            .sync_all()
            .map_err(|e| io_error("flush published file metadata", destination, e))?;
        to.sync_all()
            .map_err(|e| io_error("flush publication directory", destination, e))?;
        from.sync_all()
            .map_err(|e| io_error("flush staging directory after rename", staged, e))?;
        let published = self.readback(destination, root)?.ok_or_else(|| {
            failure(
                StateFileErrorCode::SourceChanged,
                "published file absent on readback",
                destination,
            )
        })?;
        if metadata(&published, destination, false, true)? != before {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "published object differs from staging pin",
                destination,
            ));
        }
        if self.readback(staged, root)?.is_some() {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "staging name remained after publication",
                staged,
            ));
        }
        Ok(())
    }
}
