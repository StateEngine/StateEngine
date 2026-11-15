//! Journal revisions are reusable only while a native pin excludes all writers.
use std::{
    fs::File,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, ReOpenFile},
    System::{IO::DeviceIoControl, Ioctl::FSCTL_READ_FILE_USN_DATA},
};

#[repr(align(8))]
struct RecordBuffer([u8; 4096]);

/// Reopen the exact retained file object, never its possibly replaced pathname.
/// Denying write sharing excludes a live writer whose repeated writes may share
/// one journal record. Failure leaves the caller on its bounded full-hash path.
pub(super) fn pin(file: &File) -> Option<File> {
    // SAFETY: borrowed live file handle and documented read/share flags. A new
    // native handle is returned on success; no ownership of the input transfers.
    let raw = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            0,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: successful ReOpenFile returned a new uniquely owned native handle.
    Some(unsafe { File::from_raw_handle(raw) })
}

/// Qualify every key capture, including hint publication outside hash_image.
/// A full hash performed while a writer lives must not publish that writer's
/// coalesced revision as reusable. Zero and unsupported journals also miss.
pub(super) fn revision(file: &File) -> Option<i64> {
    let pin = pin(file)?;
    let mut output = RecordBuffer([0; 4096]);
    let mut returned = 0;
    // SAFETY: retained file handle, no input/overlapped operation, and a writable
    // aligned bounded byte buffer whose exact size accompanies its pointer.
    if unsafe {
        DeviceIoControl(
            pin.as_raw_handle(),
            FSCTL_READ_FILE_USN_DATA,
            ptr::null(),
            0,
            output.0.as_mut_ptr().cast(),
            output.0.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return None;
    }
    let bytes = output.0.get(..returned as usize)?;
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let major = u16::from_le_bytes(bytes.get(4..6)?.try_into().ok()?);
    let offset = match major {
        2 => 24,
        3 => 40,
        _ => return None,
    };
    if length > bytes.len() || length < offset + 8 {
        return None;
    }
    let revision = i64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?);
    (revision > 0).then_some(revision)
}
