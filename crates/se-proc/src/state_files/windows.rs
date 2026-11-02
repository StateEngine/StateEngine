use super::*;
#[path = "effects/windows.rs"]
pub(super) mod effects;
use std::{
    mem::{size_of, zeroed},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Component,
    ptr,
};
use windows_sys::Win32::{Foundation::*, Security::*, Storage::FileSystem::*};

pub(crate) mod security;
use security::descriptor;
fn validate_component(value: &std::ffi::OsStr, path: &Path) -> Result<()> {
    let units: Vec<_> = value.encode_wide().collect();
    if units.contains(&(b':' as u16))
        || units
            .last()
            .is_some_and(|unit| *unit == b'.' as u16 || *unit == b' ' as u16)
    {
        return Err(unsafe_path("ambiguous native path component", path));
    }
    Ok(())
}
pub(crate) fn wide(path: &Path) -> Result<Vec<u16>> {
    use std::path::Prefix;
    for component in path.components() {
        match component {
            Component::Normal(value) => validate_component(value, path)?,
            Component::Prefix(_) | Component::RootDir => (),
            _ => return Err(unsafe_path("normalized native path required", path)),
        }
    }
    let units: Vec<_> = path.as_os_str().encode_wide().collect();
    let prefix = path.components().next();
    let mut value: Vec<u16> = match prefix {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => units,
            Prefix::Disk(_) if path.is_absolute() => {
                "\\\\?\\".encode_utf16().chain(units).collect()
            }
            Prefix::UNC(_, _) => "\\\\?\\UNC\\"
                .encode_utf16()
                .chain(units.into_iter().skip(2))
                .collect(),
            _ => {
                return Err(unsafe_path(
                    "absolute disk or UNC state path required",
                    path,
                ));
            }
        },
        _ => return Err(unsafe_path("absolute native state path required", path)),
    };
    for unit in &mut value {
        if *unit == b'/' as u16 {
            *unit = b'\\' as u16;
        }
    }
    if value.contains(&0) || value.len() >= 32767 {
        return Err(unsafe_path(
            "bounded native path without NUL required",
            path,
        ));
    }
    value.push(0);
    Ok(value)
}
fn last(operation: &'static str, path: &Path) -> StateFileError {
    io_error(operation, path, io::Error::last_os_error())
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Identity {
    volume: u64,
    index: [u8; 16],
}
fn metadata(file: &File, path: &Path, directory: bool, check_security: bool) -> Result<Identity> {
    let info = crate::windows_native::file_information(file)
        .map_err(|e| io_error("read pinned native file identity", path, e))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        // SAFETY: immutable query of this retained native handle.
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
        security::verify(file, path, !directory)?;
    }
    let id = crate::windows_native::file_id(file)
        .map_err(|e| io_error("read 128-bit native file identity", path, e))?;
    Ok(Identity {
        volume: id.volume,
        index: id.index,
    })
}
fn open(path: &Path, directory: bool, create: bool, write: bool) -> Result<File> {
    let data = wide(path)?;
    let descriptor = if create {
        Some(descriptor(path, directory)?)
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
    let share = FILE_SHARE_READ
        | if directory || !create {
            FILE_SHARE_WRITE
        } else {
            0
        }
        | if directory { 0 } else { FILE_SHARE_DELETE };
    // SAFETY: retained UTF-16 path and optional descriptor outlive this native open.
    let raw = unsafe {
        CreateFileW(
            data.as_ptr(),
            GENERIC_READ | READ_CONTROL | if write { GENERIC_WRITE } else { 0 },
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
                prefix.push(n);
                if create {
                    let parent_path = prefix
                        .parent()
                        .ok_or_else(|| unsafe_path("directory parent missing", &prefix))?;
                    let sd = descriptor(&prefix, true)?;
                    let sa = SECURITY_ATTRIBUTES {
                        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                        lpSecurityDescriptor: sd.0,
                        bInheritHandle: 0,
                    };
                    // SAFETY: valid descriptor and terminated native path outlive creation.
                    let created = unsafe { CreateDirectoryW(wide(&prefix)?.as_ptr(), &sa) };
                    if created == 0 {
                        // SAFETY: reads this thread's immediately preceding native error.
                        if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
                            return Err(last("create protected directory", &prefix));
                        }
                    } else {
                        let parent = open(parent_path, true, false, true)?;
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
            let file = open(&prefix, true, false, true)?;
            metadata(&file, &prefix, true, true)?;
            file
        } else {
            let data = wide(&prefix)?;
            // SAFETY: terminated path, no-follow query handle for ancestor inspection.
            let raw = unsafe {
                CreateFileW(
                    data.as_ptr(),
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
            // SAFETY: successful open transfers one uniquely owned handle.
            let mut file = unsafe { File::from_raw_handle(raw) };
            // SAFETY: POD output buffer, live handle and writable output.
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            // SAFETY: immutable metadata query using the retained ancestor handle.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                return Err(last("read native ancestor", &prefix));
            }
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                security::verify_system_ancestor(&file, &prefix)?;
                // SAFETY: only this inspected trusted system ancestor may resolve a reparse point.
                let raw = unsafe {
                    CreateFileW(
                        data.as_ptr(),
                        FILE_READ_ATTRIBUTES | READ_CONTROL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        ptr::null(),
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        ptr::null_mut(),
                    )
                };
                if raw == INVALID_HANDLE_VALUE || raw.is_null() {
                    return Err(last("resolve trusted native ancestor", &prefix));
                }
                // SAFETY: successful open transfers one uniquely owned handle.
                file = unsafe { File::from_raw_handle(raw) };
                security::verify_system_ancestor(&file, &prefix)?;
            }
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
    resolved_root: PathBuf,
}
impl Directory {
    pub fn open(path: &Path) -> Result<Self> {
        let file = walk(path, false, None)?;
        let identity = metadata(&file, path, true, true)?;
        let mut buffer = vec![0u16; 32768];
        // SAFETY: retained directory handle, writable UTF-16 buffer and explicit
        // capacity. Resolve once from the pinned object, not a caller pathname.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if length == 0 {
            return Err(last("resolve held state directory", path));
        }
        if length as usize >= buffer.len() {
            return Err(unsafe_path(
                "resolved state directory exceeds native path capacity",
                path,
            ));
        }
        let resolved_root = std::ffi::OsString::from_wide(&buffer[..length as usize]).into();
        Ok(Self {
            file,
            identity,
            resolved_root,
        })
    }
    pub fn check_name(&self, path: &Path) -> Result<()> {
        let found = walk(path, false, None)?;
        if metadata(&found, path, true, true)? != self.identity {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "held state directory was replaced",
                path,
            ));
        }
        metadata(&self.file, path, true, true)?;
        Ok(())
    }
    fn absolute(&self, path: &Path, root: &Path) -> Result<PathBuf> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| unsafe_path("path outside held root", path))?;
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(unsafe_path("normalized relative state path required", path));
        }
        Ok(self.resolved_root.join(relative))
    }
    fn parent(&self, path: &Path, root: &Path) -> Result<File> {
        let path = self.absolute(path, root)?;
        walk(
            path.parent()
                .ok_or_else(|| unsafe_path("file parent missing", &path))?,
            false,
            Some(&self.resolved_root),
        )
    }
    pub fn prepare_directory(&self, path: &Path, root: &Path) -> Result<()> {
        let parent = self.parent(path, root)?;
        let absolute = self.absolute(path, root)?;
        let descriptor = descriptor(path, true)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: resolved held-root descendant, retained parent and descriptor;
        // this creates one leaf only and never changes an existing directory.
        if unsafe { CreateDirectoryW(wide(&absolute)?.as_ptr(), &attributes) } == 0
            && io::Error::last_os_error().raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32)
        {
            return Err(last("create protected child directory", path));
        }
        let file = open(&absolute, true, false, true)?;
        let before = metadata(&file, path, true, true)?;
        file.sync_all()
            .map_err(|e| io_error("flush protected child directory", path, e))?;
        parent
            .sync_all()
            .map_err(|e| io_error("flush protected child parent", path, e))?;
        let outside = open(&absolute, true, false, true)?;
        if metadata(&outside, path, true, true)? != before {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "prepared directory changed on readback",
                path,
            ));
        }
        Ok(())
    }
    pub fn create_staging_at(&self, path: &Path, root: &Path) -> Result<File> {
        let parent = self.parent(path, root)?;
        let file = open(&self.absolute(path, root)?, false, true, true)?;
        metadata(&file, path, false, true)?;
        parent
            .sync_all()
            .map_err(|e| io_error("flush staging parent", path, e))?;
        Ok(file)
    }
    pub fn open_for_publication(&self, path: &Path, root: &Path) -> Result<File> {
        let _parent = self.parent(path, root)?;
        let file = open(&self.absolute(path, root)?, false, false, true)?;
        metadata(&file, path, false, true)?;
        Ok(file)
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
        let file = match open(&self.absolute(path, root)?, false, false, false) {
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
    pub fn publish(
        &self,
        staged: &Path,
        destination: &Path,
        root: &Path,
        source: &File,
    ) -> Result<()> {
        let from = self.parent(staged, root)?;
        let to = self.parent(destination, root)?;
        // SAFETY: terminated native paths and no replacement/copy flags.
        // No REPLACE_EXISTING or COPY_ALLOWED: an existing destination is never
        // overwritten, and a different volume cannot turn rename into a copy.
        if unsafe {
            MoveFileExW(
                wide(&self.absolute(staged, root)?)?.as_ptr(),
                wide(&self.absolute(destination, root)?)?.as_ptr(),
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
        Ok(())
    }
}

pub(super) fn random(path: &Path) -> Result<[u8; 16]> {
    let mut bytes = [0; 16];
    crate::fill_entropy(&mut bytes)
        .map_err(|e| io_error("native staging entropy", path, io::Error::other(e)))?;
    Ok(bytes)
}
pub(super) fn identity(file: &File, path: &Path) -> Result<Identity> {
    metadata(file, path, false, true)
}
