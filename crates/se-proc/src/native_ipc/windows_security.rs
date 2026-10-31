//! Aligned token buffers and LocalFree-owned descriptor/SID allocations stay
//! alive for every native call that borrows them. Handles are never inherited.
use super::*;
use std::{
    ffi::OsStr,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
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
fn token_user(process: HANDLE) -> IpcNativeResult<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: retained query-capable process handle and writable output for one owned noninherited token handle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("open IPC peer token"));
    }
    // SAFETY: successful OpenProcessToken transfers one unique token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut length = 0;
    // SAFETY: live token; null/zero sizing buffer and initialized writable byte-count output.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if length < size_of::<TOKEN_USER>() as u32 || length > 65536 {
        return Err(last("size IPC peer SID"));
    }
    let mut storage = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: pointer-aligned retained storage of the exact probed size; the
    // token is held and the API may not write beyond the supplied capacity.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(last("read IPC peer SID"));
    }
    // SAFETY: successful TOKEN_USER output in retained pointer-aligned storage.
    let sid = unsafe { (*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_text(sid)
}
fn sid_text(sid: PSID) -> IpcNativeResult<String> {
    // SAFETY: a non-null SID is borrowed from the retained successful native security output.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid native IPC SID",
        ));
    }
    let mut raw = ptr::null_mut();
    // SAFETY: validated retained SID and writable output for a LocalFree-owned UTF-16 string.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(last("encode IPC SID"));
    }
    let allocation = Allocation(raw.cast());
    let mut length = 0;
    // SAFETY: the retained native conversion result is a NUL-terminated SID string, scanned only to its bounded length.
    while length < 256 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "oversized native SID",
        ));
    }
    // SAFETY: the measured UTF-16 extent remains in the retained native conversion allocation.
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| refuse(IpcNativeErrorCode::Unreadable, "invalid SID text"))?;
    drop(allocation);
    Ok(value)
}
pub(super) fn current_sid() -> IpcNativeResult<String> {
    // SAFETY: GetCurrentProcess returns the documented borrowed pseudo handle, not an owned allocation.
    token_user(unsafe { GetCurrentProcess() })
}
pub(super) fn process_sid(process: HANDLE) -> IpcNativeResult<String> {
    token_user(process)
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
