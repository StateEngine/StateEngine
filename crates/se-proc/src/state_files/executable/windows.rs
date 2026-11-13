//! Short-lived pathname stability for native CreateProcess image selection.
use crate::state_files::{Result, io_error, unsafe_path, windows::wide};
use std::{fs::File, os::windows::io::FromRawHandle, path::Path, ptr};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};

pub(super) fn lock(path: &Path) -> Result<Vec<File>> {
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path("executable parent absent", path))?;
    let mut parents: Vec<_> = parent.ancestors().collect();
    parents.reverse();
    let mut files = Vec::with_capacity(parents.len() + 1);
    // Lock from the volume/share root down. Each subsequent open is reached
    // through already-held components, so a directory rename cannot redirect it.
    for directory in parents {
        files.push(open(directory, true)?);
    }
    files.push(open(path, false)?);
    Ok(files)
}

fn open(path: &Path, directory: bool) -> Result<File> {
    let name = wide(path)?;
    // SAFETY: terminated native path and no inherited handles. Directory handles
    // deny writes and deletion, including directory reparse-point changes. All
    // handles remain owned by the invocation through native process creation.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            if directory {
                FILE_READ_ATTRIBUTES
            } else {
                GENERIC_READ | READ_CONTROL
            },
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io_error(
            "hold executable path through creation",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful CreateFileW transferred one unique owned handle.
    let file = unsafe { File::from_raw_handle(raw) };
    let info = crate::windows_native::file_information(&file)
        .map_err(|error| io_error("inspect executable path component", path, error))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(unsafe_path(
            "executable path component changed kind or is a reparse point",
            path,
        ));
    }
    Ok(file)
}
