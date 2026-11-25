//! Shared Windows process-query primitives. Callers retain their handles/token buffers;
//! typed adapters add their own operation context without copying native walks.
pub use se_native_path::windows::{acl, allocation};
pub use se_state_files::windows_attributes::{self as attributes, Error};
mod parent;
mod process_query;
pub use parent::parent;
pub use process_query::{Query, maps_executable, query};
use std::{
    collections::BTreeMap,
    io,
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

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
/// # Safety
/// `raw` must be null, `INVALID_HANDLE_VALUE`, or a handle whose sole ownership is
/// transferred to this call: newly created/opened, or an inherited entry the
/// caller sealed.
pub unsafe fn handle(raw: HANDLE, operation: &'static str) -> Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(last(operation));
    }
    // SAFETY: successful native creation/open transfers exactly one new reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
/// # Safety
/// `sid` must point to a valid Windows SID whose backing buffer remains alive for this call.
pub unsafe fn sid_text(sid: PSID) -> Result<String> {
    // SAFETY: callers retain the native token or descriptor that owns this SID.
    unsafe { se_native_path::windows::sid::text(sid) }.map_err(|source| Error {
        operation: "encode native SID",
        source,
    })
}
/// # Safety
/// `process` must be a valid query-capable Windows process handle (or current-process pseudo handle).
pub unsafe fn process_sid(process: HANDLE) -> Result<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: retained query-capable process and writable owned-token output.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("open native process owner token"));
    }
    // SAFETY: OpenProcessToken transferred sole ownership of `raw` on success.
    let token = unsafe { handle(raw, "open native process owner token") }?;
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
    unsafe { sid_text((*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid) }
}
/// # Safety
/// `process` must be a valid query-capable Windows process handle (or current-process pseudo handle).
pub unsafe fn process_start(process: HANDLE) -> Result<u64> {
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
pub fn parents() -> Result<BTreeMap<u32, u32>> {
    // SAFETY: CreateToolhelp32Snapshot transfers a newly opened snapshot handle on success.
    let snapshot = unsafe {
        handle(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0),
            "snapshot native ancestry",
        )
    }?;
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
