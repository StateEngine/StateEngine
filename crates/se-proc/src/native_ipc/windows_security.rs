//! Aligned token buffers and LocalFree-owned descriptor/SID allocations stay
//! alive for every native call that borrows them. Handles are never inherited.
use super::*;
use crate::windows_native::allocation::Allocation;
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::Threading::*,
};

fn sid_text(sid: PSID) -> IpcNativeResult<String> {
    crate::windows_native::sid_text(sid).map_err(|e| error(e.operation, e.source))
}
pub(super) fn current_sid() -> IpcNativeResult<String> {
    // SAFETY: GetCurrentProcess returns the documented borrowed pseudo handle, not an owned allocation.
    process_sid(unsafe { GetCurrentProcess() })
}
pub(super) fn process_sid(process: HANDLE) -> IpcNativeResult<String> {
    crate::windows_native::process_sid(process).map_err(|e| error(e.operation, e.source))
}
pub(super) fn descriptor() -> IpcNativeResult<Allocation> {
    let sid = current_sid()?;
    let text = format!("O:{sid}D:P(A;;GA;;;{sid})");
    let wide: Vec<u16> = OsStr::new(&text).encode_wide().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    // SAFETY: retained NUL-terminated SDDL, exact revision and writable LocalFree-owned descriptor output.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last("create owner-only IPC descriptor"));
    }
    Ok(Allocation(raw))
}
pub(super) fn verify(handle: HANDLE) -> IpcNativeResult<()> {
    let descriptor = crate::windows_native::acl::SecurityDescriptor::query(
        handle,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )
    .map_err(|e| error("read IPC pipe protection", e))?;
    let current = current_sid()?;
    let control = descriptor
        .control()
        .map_err(|e| error("read IPC DACL control", e))?;
    if descriptor.owner.is_null()
        || sid_text(descriptor.owner)? != current
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "protected current-user IPC DACL required",
        ));
    }
    let dacl = descriptor.dacl().ok_or_else(|| {
        refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "protected current-user IPC DACL required",
        )
    })?;
    if dacl.len() == 0 {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC DACL has no owner grant",
        ));
    }
    for index in 0..dacl.len() {
        let entry = dacl
            .ace(index)
            .map_err(|e| error("read IPC protection ACE", e))?;
        let ace = entry
            .allowed()
            .filter(|_| u32::from(entry.header().AceFlags) & INHERITED_ACE == 0)
            .ok_or_else(|| {
                refuse(
                    IpcNativeErrorCode::UnsafeEndpoint,
                    "unexpected IPC protection ACE",
                )
            })?;
        if sid_text((&raw const ace.SidStart).cast_mut().cast())? != current {
            return Err(refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC DACL grants another user access",
            ));
        }
    }
    Ok(())
}

/// Diagnostic only; a named owner read grants no pipe/client authority. ACLs
/// can refuse READ_CONTROL, in which case the caller retains that exact cause.
pub(super) fn named_owner(name: &[u16]) -> IpcNativeResult<String> {
    let descriptor = crate::windows_native::acl::SecurityDescriptor::named_owner(name)
        .map_err(|e| error("read existing pipe owner SID", e))?;
    sid_text(descriptor.owner)
}
