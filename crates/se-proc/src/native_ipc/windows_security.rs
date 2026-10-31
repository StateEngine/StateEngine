//! Aligned token buffers and LocalFree-owned descriptor/SID allocations stay
//! alive for every native call that borrows them. Handles are never inherited.
use super::*;
use std::{ffi::OsStr, mem::size_of, os::windows::ffi::OsStrExt, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{SystemServices::ACCESS_ALLOWED_ACE_TYPE, Threading::*},
};
pub(super) struct Allocation(pub *mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this exact non-null allocation was returned by a LocalFree-family security API and is uniquely owned.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
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
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut raw = ptr::null_mut();
    // SAFETY: a live pipe handle and aligned pointer outputs; every returned
    // SID/ACE is borrowed only while the LocalFree descriptor is retained.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut raw,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(error(
            "read IPC pipe protection",
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    let allocation = Allocation(raw);
    let current = current_sid()?;
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: retained native descriptor and initialized writable control/revision outputs.
    if unsafe { GetSecurityDescriptorControl(allocation.0, &mut control, &mut revision) } == 0 {
        return Err(last("read IPC DACL control"));
    }
    if owner.is_null()
        || sid_text(owner)? != current
        || dacl.is_null()
        || control & SE_DACL_PROTECTED == 0
        // SAFETY: this non-null ACL is inside the retained successful native security descriptor.
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "protected current-user IPC DACL required",
        ));
    }
    // SAFETY: IsValidAcl succeeded above; the descriptor retaining this aligned ACL is still alive.
    let count = unsafe { (*dacl).AceCount };
    if count == 0 {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC DACL has no owner grant",
        ));
    }
    for index in 0..count {
        let mut raw = ptr::null_mut();
        // SAFETY: valid retained ACL, in-range ACE index and writable borrowed-ACE output.
        if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 {
            return Err(last("read IPC protection ACE"));
        }
        // SAFETY: successful GetAce on the validated ACL supplies a retained aligned ACE_HEADER.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) & INHERITED_ACE != 0
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "unexpected IPC protection ACE",
            ));
        }
        // SAFETY: GetAce succeeded, and type/size checks above establish the
        // aligned native ACE layout before its SID field is inspected.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        if sid_text((&ace.SidStart as *const u32).cast_mut().cast())? != current {
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
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: retained NUL-terminated native name and initialized writable SID/descriptor outputs; only OWNER is requested.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _allocation = Allocation(descriptor);
    if status != ERROR_SUCCESS {
        return Err(error(
            "read existing pipe owner SID",
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    sid_text(owner)
}
