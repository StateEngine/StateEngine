//! Bind a file revision to the journal instance that assigned it.
use std::{
    fs::File,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        CreateFileW, FILE_NAME_OPENED, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_GUID,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{FSCTL_QUERY_USN_JOURNAL, USN_JOURNAL_DATA_V0},
    },
};

/// Resolve the volume from the retained file, without following its pathname or
/// a mutable drive letter. Unsupported namespaces and unavailable access miss.
pub(super) fn volume(file: &File) -> Option<File> {
    let mut path = vec![0u16; 32768];
    // SAFETY: retained file handle, bounded writable UTF-16 buffer.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            FILE_NAME_OPENED | VOLUME_NAME_GUID,
        )
    } as usize;
    if length == 0 || length >= path.len() {
        return None;
    }
    let path = String::from_utf16(&path[..length]).ok()?;
    let (guid, _) = path.strip_prefix(r"\\?\Volume{")?.split_once("}\\")?;
    if guid.len() != 36
        || !guid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    // No trailing slash: open the volume itself, not its root directory.
    let name: Vec<u16> = format!(r"\\?\Volume{{{guid}}}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: validated NUL-terminated native volume name; metadata-only access,
    // documented device sharing and no mutation or ownership transfer.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: successful CreateFileW returned a new uniquely owned handle.
    Some(unsafe { File::from_raw_handle(raw) })
}

pub(super) fn read(volume: &File) -> Option<USN_JOURNAL_DATA_V0> {
    let mut data = USN_JOURNAL_DATA_V0::default();
    let mut returned = 0;
    // SAFETY: retained volume handle, initialized aligned native output with its
    // exact capacity, no input and a synchronous operation.
    let succeeded = unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            FSCTL_QUERY_USN_JOURNAL,
            ptr::null(),
            0,
            (&mut data as *mut USN_JOURNAL_DATA_V0).cast(),
            size_of::<USN_JOURNAL_DATA_V0>() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    (succeeded != 0 && returned as usize == size_of::<USN_JOURNAL_DATA_V0>()).then_some(data)
}
