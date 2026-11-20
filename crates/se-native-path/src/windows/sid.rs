//! Raw conversion of a retained native SID to text.
use super::allocation::Allocation;
use std::{io, ptr};
use windows_sys::Win32::Security::{Authorization::ConvertSidToStringSidW, IsValidSid, PSID};
/// # Safety
/// A non-null SID must point into a retained native token or security descriptor.
pub unsafe fn text(sid: PSID) -> io::Result<String> {
    // SAFETY: callers retain the successful native token/security buffer containing this SID.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native SID",
        ));
    }
    let mut raw = ptr::null_mut();
    // SAFETY: validated retained SID and writable LocalFree-owned output.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the native API returned a unique LocalFree allocation.
    let _text = unsafe { Allocation::from_raw(raw.cast()) };
    let mut length = 0;
    // SAFETY: successful native conversion supplies a terminated SID string;
    // the allocation remains retained for this bounded scan and copy.
    while length < 256 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native SID text exceeds 256 units",
        ));
    }
    // SAFETY: measured extent belongs to the retained native allocation.
    String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) }).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native SID text is invalid UTF-16",
        )
    })
}
