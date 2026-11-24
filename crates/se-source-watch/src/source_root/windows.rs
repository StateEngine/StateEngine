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
/// What the no-reparse open already read from the opened handle.
pub(super) type Facts = BY_HANDLE_FILE_INFORMATION;

pub(super) fn open_root(path: &Path) -> io::Result<File> {
    let name = se_state_files::state_files::windows::wide(path)
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
    // SAFETY: CreateFileW returned a newly opened handle owned by this process.
    unsafe { owned(raw) }
}
pub(super) fn open_relative(root: &File, path: &str) -> io::Result<(File, Facts)> {
    open_components(root, path, false)
}
pub(super) fn open_directory(root: &File, path: &str) -> io::Result<(File, Facts)> {
    open_components(root, path, true)
}
pub(super) fn open_component(
    parent: &File,
    part: &str,
    is_directory: bool,
) -> io::Result<(File, Facts)> {
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
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut name,
        // Exact spelling avoids aliasing collisions in case-sensitive dirs.
        Attributes: 0,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
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
    // SAFETY: NtCreateFile returned a newly created handle owned by this process.
    let child = unsafe { owned(raw) }?;
    let facts = verify_handle(&child, is_directory)?;
    Ok((child, facts))
}
fn open_components(root: &File, path: &str, last_directory: bool) -> io::Result<(File, Facts)> {
    let mut held: Option<(File, Facts)> = None;
    let mut components = path.split('/').peekable();
    while let Some(part) = components.next() {
        let is_directory = components.peek().is_some() || last_directory;
        let parent = held.as_ref().map_or(root, |(file, _)| file);
        held = Some(open_component(parent, part, is_directory)?);
    }
    held.ok_or_else(|| invalid("bounded slash-separated root-relative source path required"))
}
/// # Safety
/// `raw` must be null, `INVALID_HANDLE_VALUE`, or a newly created/opened handle
/// whose sole ownership is transferred to this call.
unsafe fn owned(raw: HANDLE) -> io::Result<File> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this function's safety contract guarantees `raw`'s precondition.
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn verify_handle(file: &File, directory: bool) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let info = se_native_path::windows::file::file_information(file)?;
    // SAFETY: immutable native handle query, no retained external pointers.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(invalid(
            "regular non-reparse source file/directory required",
        ));
    }
    Ok(info)
}
pub(super) fn object_key(file: &File, _: &Facts) -> io::Result<NativeObjectKey> {
    se_state_files::observe_object_key(file)
}
pub(super) fn opened_revision(
    file: &File,
    facts: &Facts,
    directory: bool,
) -> io::Result<NativeFileRevision> {
    se_state_files::file_revision_from_information(file, facts, directory)
}
pub(super) fn revision(file: &File, directory: bool) -> io::Result<NativeFileRevision> {
    se_state_files::observe_file_revision_for(file, directory)
}
