//! Shared Windows query primitives. Callers retain their handles/token buffers;
//! typed adapters add their own operation context without copying native walks.
use std::{
    collections::BTreeMap,
    io,
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::ConvertSidToStringSidW, *},
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

pub(crate) struct Error {
    pub operation: &'static str,
    pub source: io::Error,
}
type Result<T> = std::result::Result<T, Error>;
fn last(operation: &'static str) -> Error {
    Error {
        operation,
        source: io::Error::last_os_error(),
    }
}
fn invalid(operation: &'static str, reason: &'static str) -> Error {
    Error {
        operation,
        source: io::Error::new(io::ErrorKind::InvalidData, reason),
    }
}
pub(crate) fn handle(raw: HANDLE, operation: &'static str) -> Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(last(operation));
    }
    // SAFETY: successful native creation/open transfers exactly one new reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
pub(crate) fn sid_text(sid: PSID) -> Result<String> {
    // SAFETY: callers retain the successful native token/security buffer containing this SID.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid("encode native SID", "invalid native SID"));
    }
    let mut raw = ptr::null_mut();
    // SAFETY: validated retained SID and writable LocalFree-owned output.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(last("encode native SID"));
    }
    struct Text(*mut u16);
    impl Drop for Text {
        fn drop(&mut self) {
            // SAFETY: uniquely owned allocation returned by ConvertSidToStringSidW.
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
    let text = Text(raw);
    let mut length = 0;
    // SAFETY: successful native conversion supplies a terminated SID string;
    // the allocation remains retained for this bounded scan and copy.
    while length < 256 && unsafe { *text.0.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(invalid(
            "encode native SID",
            "native SID text exceeds 256 units",
        ));
    }
    // SAFETY: measured extent belongs to the retained native allocation.
    String::from_utf16(unsafe { std::slice::from_raw_parts(text.0, length) })
        .map_err(|_| invalid("encode native SID", "native SID text is invalid UTF-16"))
}
pub(crate) fn process_sid(process: HANDLE) -> Result<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: retained query-capable process and writable owned-token output.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("open native process owner token"));
    }
    let token = handle(raw, "open native process owner token")?;
    let mut bytes = 0;
    // SAFETY: documented sizing call with null buffer and writable length output.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut bytes,
        );
    }
    if bytes < size_of::<TOKEN_USER>() as u32 || bytes > 65536 {
        return Err(invalid(
            "read native process owner",
            "native token-user size exceeds bounds",
        ));
    }
    let capacity = bytes;
    let mut storage = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: retained token and aligned initialized buffer of the exact queried capacity.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut bytes,
        )
    } == 0
    {
        return Err(last("read native process owner"));
    }
    if bytes < size_of::<TOKEN_USER>() as u32 || bytes > capacity {
        return Err(invalid(
            "read native process owner",
            "native token-user size changed",
        ));
    }
    // SAFETY: successful aligned TOKEN_USER output remains retained through SID conversion.
    sid_text(unsafe { (*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}
pub(crate) fn process_start(process: HANDLE) -> Result<u64> {
    // SAFETY: FILETIME is native POD; all outputs are initialized before use.
    let (mut created, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { zeroed() };
    // SAFETY: retained process query handle and four aligned writable outputs.
    if unsafe { GetProcessTimes(process, &mut created, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(last("read native process start"));
    }
    let value = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if value == 0 {
        return Err(invalid(
            "read native process start",
            "native process creation clock is zero",
        ));
    }
    Ok(value)
}
pub(crate) fn parents() -> Result<BTreeMap<u32, u32>> {
    let snapshot = handle(
        // SAFETY: read-only process snapshot, no heap/process mutation or pointer inputs.
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) },
        "snapshot native ancestry",
    )?;
    // SAFETY: process-entry POD is initialized and its size is set before enumeration.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: retained snapshot and exact aligned process-entry output.
    if unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } == 0 {
        return Err(last("read native ancestry snapshot"));
    }
    let mut result = BTreeMap::new();
    loop {
        if result.len() == 65536 {
            return Err(invalid(
                "read native ancestry",
                "process snapshot exceeds 65536 entries",
            ));
        }
        if result
            .insert(entry.th32ProcessID, entry.th32ParentProcessID)
            .is_some()
        {
            return Err(invalid(
                "read native ancestry",
                "duplicate native process ID",
            ));
        }
        // SAFETY: retained snapshot and initialized writable process-entry output.
        if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            let cause = io::Error::last_os_error();
            if cause.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                return Err(Error {
                    operation: "finish native ancestry snapshot",
                    source: cause,
                });
            }
            break;
        }
    }
    Ok(result)
}
