//! Native access checks for installed executables and read-only package files.
use crate::{NativeRootFile, NativeSourceRoot};
use std::{io, io::Read, path::Path};

/// Open a retained regular file before reading it. Native source opens refuse
/// special files without waiting for another endpoint, including Unix FIFOs.
pub fn with_readable_regular_file<T>(
    path: &Path,
    read: impl FnOnce(&mut NativeRootFile<'_>) -> io::Result<T>,
) -> io::Result<T> {
    let physical = crate::canonicalize_path(path)?;
    let parent = physical
        .parent()
        .ok_or_else(|| io::Error::other("installed file has no parent directory"))?;
    let name = physical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("installed file name is not UTF-8"))?;
    let root = NativeSourceRoot::open(parent)?;
    let mut file = root
        .open_relative(name)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let before = file.revision()?;
    let value = read(&mut file)?;
    if before != file.revision()? || !file.validate_name()? {
        return Err(io::Error::other("installed file changed while being read"));
    }
    Ok(value)
}

/// Refuse oversized metadata rather than parsing a silently truncated prefix.
pub fn read_bounded_regular_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    with_readable_regular_file(path, |file| {
        if file.revision()?.size > limit as u64 {
            return Err(io::Error::other("installed file exceeds its read bound"));
        }
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(io::Error::other("installed file exceeds its read bound"));
        }
        Ok(bytes)
    })
}

/// Query the caller's effective native execute access without launching code.
#[cfg(unix)]
pub fn require_executable_access(path: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: a terminated path and native permission query; no file mutation.
    let result =
        unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::X_OK, libc::AT_EACCESS) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
pub fn require_executable_access(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};
    let path = crate::state_files::windows::wide(path).map_err(io::Error::other)?;
    // SAFETY: validated terminated name; request execute access without executing
    // or writing. The successful handle is closed in this function.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_EXECUTE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful open transferred this live, uniquely owned handle.
    unsafe { CloseHandle(handle) };
    Ok(())
}
