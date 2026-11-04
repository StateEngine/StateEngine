use super::*;
use std::{
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    },
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::IO::IO_STATUS_BLOCK};

pub(super) fn open_root(path: &Path) -> io::Result<File> {
    let name = crate::state_files::windows::wide(path)
        .map_err(|_| invalid("normalized absolute source root required"))?;
    // SAFETY: validated terminated path; read-only directory custody and full
    // sharing, without following the registered root's reparse point.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    owned(raw)
}
pub(super) fn open_relative(root: &File, path: &str) -> io::Result<File> {
    let mut directory = root.try_clone()?;
    let mut components = path.split('/').peekable();
    while let Some(part) = components.next() {
        if part.ends_with(['.', ' ']) {
            return Err(invalid("ambiguous Windows source component"));
        }
        let mut units: Vec<u16> = part.encode_utf16().collect();
        if units.is_empty() || units.len() > u16::MAX as usize / 2 {
            return Err(invalid("bounded Windows source component required"));
        }
        let mut name = UNICODE_STRING {
            Length: (units.len() * 2) as u16,
            MaximumLength: (units.len() * 2) as u16,
            Buffer: units.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: directory.as_raw_handle(),
            ObjectName: &mut name,
            // Exact spelling avoids aliasing collisions in case-sensitive dirs.
            Attributes: 0,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };
        let is_directory = components.peek().is_some();
        let mut raw = ptr::null_mut();
        // SAFETY: POD native completion output initialized for the sync call.
        let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
        // SAFETY: one literal component relative to the live directory handle;
        // no ambient path lookup, no writes, reparse traversal or creation.
        let code = unsafe {
            NtCreateFile(
                &mut raw,
                GENERIC_READ | SYNCHRONIZE,
                &attributes,
                &mut status,
                ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT
                    | FILE_SYNCHRONOUS_IO_NONALERT
                    | if is_directory {
                        FILE_DIRECTORY_FILE
                    } else {
                        FILE_NON_DIRECTORY_FILE
                    },
                ptr::null(),
                0,
            )
        };
        if code < 0 {
            // SAFETY: status conversion takes no pointer arguments.
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(code) } as i32,
            ));
        }
        let child = owned(raw)?;
        revision(&child, is_directory)?;
        directory = child;
    }
    Ok(directory)
}
fn owned(raw: HANDLE) -> io::Result<File> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful native open transferred one uniquely owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
pub(super) fn revision(file: &File, directory: bool) -> io::Result<NativeFileRevision> {
    let info = crate::windows_native::file_information(file)?;
    // SAFETY: immutable native handle query, no retained external pointers.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(invalid(
            "regular non-reparse source file/directory required",
        ));
    }
    let id = crate::windows_native::file_id(file)?;
    // SAFETY: all-integer native output initialized before the metadata query.
    let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
    // SAFETY: retained handle, initialized output and its exact native size.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut volume = [0; 16];
    volume[..8].copy_from_slice(&id.volume.to_be_bytes());
    let unix_nanos = |ticks: i64| (i128::from(ticks) - 116_444_736_000_000_000) * 100;
    Ok(NativeFileRevision {
        volume,
        file: id.index,
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        mtime_unix_nanos: unix_nanos(basic.LastWriteTime),
        ctime_unix_nanos: Some(unix_nanos(basic.ChangeTime)),
    })
}
