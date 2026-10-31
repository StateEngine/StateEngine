//! Current-user protected DACL creation and handle-based readback. All native
//! SID/ACE pointers come from retained aligned GetTokenInformation or
//! LocalFree-owned GetSecurityInfo buffers, never caller-supplied bytes.
use super::super::{Result, io_error, unsafe_path};
use super::last;
use std::{
    ffi::OsStr,
    fs::File,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{SystemServices::ACCESS_ALLOWED_ACE_TYPE, Threading::*},
};
pub(super) struct Allocation(pub(super) *mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
struct User {
    storage: Vec<usize>,
}
impl User {
    fn current(path: &Path) -> Result<Self> {
        let mut raw = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(last("read current user token", path));
        }
        // SAFETY: OpenProcessToken returned unique ownership of a valid handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut length = 0;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut length,
            );
        }
        if length < size_of::<TOKEN_USER>() as u32 {
            return Err(last("size token user", path));
        }
        let mut user = Self {
            storage: vec![0; (length as usize).div_ceil(size_of::<usize>())],
        };
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                user.storage.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(last("read token user", path));
        }
        Ok(user)
    }
    fn sid(&self) -> PSID {
        // SAFETY: aligned successful TOKEN_USER buffer; its embedded SID remains
        // inside the heap allocation retained by this User through the native call.
        unsafe { (&*self.storage.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
    fn text(&self, path: &Path) -> Result<String> {
        let mut raw = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut raw) } == 0 {
            return Err(last("encode user SID", path));
        }
        let allocation = Allocation(raw.cast());
        let mut len = 0;
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
            .map_err(|_| unsafe_path("malformed native SID text", path))?;
        drop(allocation);
        Ok(text)
    }
}
pub(super) fn descriptor(path: &Path) -> Result<Allocation> {
    let sid = User::current(path)?.text(path)?;
    let sddl = format!("O:{sid}D:P(A;;FA;;;SY)(A;;FA;;;{sid})");
    let data: Vec<_> = OsStr::new(&sddl).encode_wide().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            data.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last("create protected owner DACL", path));
    }
    Ok(Allocation(raw))
}
pub(super) fn verify(file: &File, path: &Path) -> Result<()> {
    let user = User::current(path)?;
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut raw = ptr::null_mut();
    // SAFETY: live file handle with READ_CONTROL; native outputs point into one
    // LocalFree-owned security descriptor retained for every SID/ACE inspection.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
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
        return Err(io_error(
            "read file owner and DACL",
            path,
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    let allocation = Allocation(raw);
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(allocation.0, &mut control, &mut revision) } == 0 {
        return Err(last("read DACL control", path));
    }
    if owner.is_null()
        || unsafe { EqualSid(owner, user.sid()) } == 0
        || dacl.is_null()
        || control & SE_DACL_PROTECTED == 0
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(unsafe_path("owner-only protected DACL required", path));
    }
    let system_text: Vec<_> = OsStr::new("S-1-5-18")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut system = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(system_text.as_ptr(), &mut system) } == 0 {
        return Err(last("construct system SID", path));
    }
    let system = Allocation(system);
    let count = unsafe { (*dacl).AceCount };
    for index in 0..count {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 {
            return Err(last("read protection ACE", path));
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) & INHERITED_ACE != 0
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(unsafe_path("unexpected or inherited protection ACE", path));
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if unsafe { IsValidSid(sid) } == 0
            || (unsafe { EqualSid(sid, user.sid()) } == 0
                && unsafe { EqualSid(sid, system.0) } == 0)
        {
            return Err(unsafe_path("DACL grants another principal access", path));
        }
    }
    Ok(())
}
