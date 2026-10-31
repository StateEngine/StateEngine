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
            // SAFETY: this allocation was returned by a LocalFree-family native API.
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
        // SAFETY: native current-process pseudo handle and writable token output.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(last("read current user token", path));
        }
        // SAFETY: OpenProcessToken returned unique ownership of a valid handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut length = 0;
        // SAFETY: documented sizing call uses a null buffer and writable size output.
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
        // SAFETY: aligned owned buffer has exactly the capacity reported by the token API.
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
        // SAFETY: retained valid token SID and writable LocalFree-owned text output.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut raw) } == 0 {
            return Err(last("encode user SID", path));
        }
        let allocation = Allocation(raw.cast());
        let mut len = 0;
        // SAFETY: native SID conversion returns a terminated UTF-16 allocation.
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: length was measured within that retained native terminated string.
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
            .map_err(|_| unsafe_path("malformed native SID text", path))?;
        drop(allocation);
        Ok(text)
    }
}
pub(super) fn descriptor(path: &Path, directory: bool) -> Result<Allocation> {
    let sid = User::current(path)?.text(path)?;
    let flags = if directory { "OICI" } else { "" };
    let sddl = format!("O:{sid}D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;{sid})");
    let data: Vec<_> = OsStr::new(&sddl).encode_wide().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    // SAFETY: owned terminated SDDL input and writable LocalFree-owned output.
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
fn sid(text: &str, path: &Path) -> Result<Allocation> {
    let text: Vec<_> = OsStr::new(text).encode_wide().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    // SAFETY: terminated constant SID text; the returned SID is LocalFree-owned.
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) } == 0 {
        return Err(last("construct native SID", path));
    }
    Ok(Allocation(raw))
}
fn equal(left: PSID, right: PSID) -> bool {
    // SAFETY: callers supply retained native descriptor/token/allocated SID pointers.
    !left.is_null() && !right.is_null() && unsafe { EqualSid(left, right) } != 0
}
fn security(file: &File, path: &Path, dacl: bool) -> Result<(Allocation, PSID, *mut ACL)> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut raw = ptr::null_mut();
    // SAFETY: retained file handle with READ_CONTROL and valid native output slots;
    // every output pointer remains inside the returned LocalFree-owned descriptor.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | if dacl { DACL_SECURITY_INFORMATION } else { 0 },
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut raw,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io_error(
            "read file security",
            path,
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    Ok((Allocation(raw), owner, acl))
}
pub(super) fn verify_system_ancestor(file: &File, path: &Path) -> Result<()> {
    let user = User::current(path)?;
    let (_descriptor, owner, _) = security(file, path, false)?;
    let system = sid("S-1-5-18", path)?;
    let administrators = sid("S-1-5-32-544", path)?;
    if !equal(owner, user.sid()) && !equal(owner, system.0) && !equal(owner, administrators.0) {
        return Err(unsafe_path(
            "reparse ancestor owner must be user or system administrator",
            path,
        ));
    }
    Ok(())
}
pub(super) fn verify(
    file: &File,
    path: &Path,
    inherited_from_protected_parent: bool,
) -> Result<()> {
    let user = User::current(path)?;
    let (descriptor, owner, dacl) = security(file, path, true)?;
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: retained native security descriptor and initialized scalar outputs.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(last("read DACL control", path));
    }
    // SAFETY: DACL came from GetSecurityInfo and remains inside descriptor.
    if !equal(owner, user.sid()) || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(unsafe_path("owner-only valid DACL required", path));
    }
    let protected = control & SE_DACL_PROTECTED != 0;
    if !protected && !inherited_from_protected_parent {
        return Err(unsafe_path("protected directory DACL required", path));
    }
    let system = sid("S-1-5-18", path)?;
    // SAFETY: IsValidAcl validated this retained native ACL before header access.
    let count = unsafe { (*dacl).AceCount };
    let mut has_user = false;
    let mut has_system = false;
    for index in 0..count {
        let mut raw = ptr::null_mut();
        // SAFETY: bounded ACL index and output pointer; descriptor outlives the ACE.
        if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 {
            return Err(last("read protection ACE", path));
        }
        // SAFETY: GetAce returns an ACE_HEADER inside the validated retained ACL.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        let inherited = u32::from(header.AceFlags) & INHERITED_ACE != 0;
        let allowed_flags = INHERITED_ACE | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) & !allowed_flags != 0
            || (!protected && !inherited)
            || (inherited && !inherited_from_protected_parent)
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(unsafe_path("unexpected protection ACE", path));
        }
        // SAFETY: allowed ACE type/size established before accessing mask and SID.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let principal = (&ace.SidStart as *const u32).cast_mut().cast();
        // SAFETY: SID is embedded in this validated native allowed ACE.
        if unsafe { IsValidSid(principal) } == 0
            || ace.Mask != windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS
        {
            return Err(unsafe_path(
                "full-control user or SYSTEM ACE required",
                path,
            ));
        }
        let is_user = equal(principal, user.sid());
        let is_system = equal(principal, system.0);
        if !is_user && !is_system {
            return Err(unsafe_path("DACL grants another principal access", path));
        }
        if !inherited_from_protected_parent
            && u32::from(header.AceFlags) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                != OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        {
            return Err(unsafe_path(
                "directory ACE must protect inherited SQLite side files",
                path,
            ));
        }
        has_user |= is_user;
        has_system |= is_system;
    }
    if !has_user || !has_system {
        return Err(unsafe_path(
            "user and SYSTEM full-control ACEs required",
            path,
        ));
    }
    Ok(())
}
