//! A qualified file revision binds writer exclusion to its journal instance.
use std::{
    fs::File,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_NAME_OPENED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFinalPathNameByHandleW, OPEN_EXISTING, ReOpenFile, VOLUME_NAME_GUID,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_FILE_USN_DATA, USN_JOURNAL_DATA_V0},
    },
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
/// Returns a qualified NTFS USN journal revision when the caller can query the
/// volume; returns `None` for non-admin callers or unsupported filesystems so
/// `hash_image` hashes directly instead of trusting a mutable timestamp.
pub(super) fn revision(file: &File) -> Option<(i64, u64)> {
    let pin = pin(file)?;
    usn_revision(&pin)
}

fn usn_revision(pin: &File) -> Option<(i64, u64)> {
    let volume = volume(pin)?;
    let before = journal(&volume)?;
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
    let after = journal(&volume)?;
    (revision > 0
        && before.UsnJournalID != 0
        && before.UsnJournalID == after.UsnJournalID
        && revision >= before.LowestValidUsn
        && revision >= after.LowestValidUsn
        && revision < after.NextUsn)
        .then_some((revision, after.UsnJournalID))
}

/// Resolve the volume from the retained file, without following its pathname or
/// a mutable drive letter. Unsupported namespaces and unavailable access miss.
fn volume(file: &File) -> Option<File> {
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
    // No trailing slash: open the volume itself, not its root directory.
    let name: Vec<u16> = format!(r"\\?\Volume{{{guid}}}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: validated NUL-terminated native volume name; read-only access
    // for journal queries, documented sharing and no mutation or ownership transfer.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
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

fn journal(volume: &File) -> Option<USN_JOURNAL_DATA_V0> {
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
