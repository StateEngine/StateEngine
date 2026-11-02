//! Current-user protected DACL creation and handle-based readback. All native
//! SID/ACE pointers come from retained aligned GetTokenInformation or
//! LocalFree-owned GetSecurityInfo buffers, never caller-supplied bytes.
use super::super::{Result, io_error, unsafe_path};
use super::last;
use crate::windows_native::allocation::Allocation;
use std::{
    ffi::OsStr,
    fs::File,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Security::{Authorization::*, *},
    System::{SystemServices::ACCESS_DENIED_ACE_TYPE, Threading::*},
};

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
        crate::windows_native::sid_text(self.sid())
            .map_err(|e| io_error(e.operation, path, e.source))
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
fn security(
    file: &File,
    path: &Path,
    dacl: bool,
) -> Result<crate::windows_native::acl::SecurityDescriptor> {
    crate::windows_native::acl::SecurityDescriptor::query(
        file.as_raw_handle(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | if dacl { DACL_SECURITY_INFORMATION } else { 0 },
    )
    .map_err(|e| io_error("read file security", path, e))
}
pub(super) fn verify_system_ancestor(file: &File, path: &Path) -> Result<()> {
    let user = User::current(path)?;
    let descriptor = security(file, path, false)?;
    let owner = descriptor.owner;
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
pub(in crate::state_files) fn verify_owner(file: &File, path: &Path) -> Result<()> {
    let user = User::current(path)?;
    let descriptor = security(file, path, false)?;
    let owner = descriptor.owner;
    if !equal(owner, user.sid()) {
        return Err(unsafe_path("file owner differs from current OS user", path));
    }
    Ok(())
}
pub(crate) fn verify(
    file: &File,
    path: &Path,
    inherited_from_protected_parent: bool,
) -> Result<()> {
    let user = User::current(path)?;
    let descriptor = security(file, path, true)?;
    let control = descriptor
        .control()
        .map_err(|e| io_error("read DACL control", path, e))?;
    if !equal(descriptor.owner, user.sid()) {
        return Err(unsafe_path("owner-only valid DACL required", path));
    }
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| unsafe_path("owner-only valid DACL required", path))?;
    let protected = control & SE_DACL_PROTECTED != 0;
    if !protected && !inherited_from_protected_parent {
        return Err(unsafe_path("protected directory DACL required", path));
    }
    let system = sid("S-1-5-18", path)?;
    let count = dacl.len();
    let mut has_user = false;
    let mut has_system = false;
    for index in 0..count {
        let entry = dacl
            .ace(index)
            .map_err(|e| io_error("read protection ACE", path, e))?;
        let header = entry.header();
        let inherited = u32::from(header.AceFlags) & INHERITED_ACE != 0;
        let allowed_flags = INHERITED_ACE | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        if u32::from(header.AceFlags) & !allowed_flags != 0
            || (!protected && !inherited)
            || (inherited && !inherited_from_protected_parent)
        {
            return Err(unsafe_path("unexpected protection ACE", path));
        }
        let ace = entry
            .allowed()
            .ok_or_else(|| unsafe_path("unexpected protection ACE", path))?;
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

/// Installation records and the permanent claim must not grant another native
/// user write/delete/security authority. Read-only grants do not confer control.
pub(in crate::state_files) fn verify_no_foreign_writer(file: &File, path: &Path) -> Result<()> {
    let user = User::current(path)?;
    let descriptor = security(file, path, true)?;
    if !equal(descriptor.owner, user.sid()) {
        return Err(unsafe_path(
            "current-user owned valid installation DACL required",
            path,
        ));
    }
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| unsafe_path("current-user owned valid installation DACL required", path))?;
    let system = sid("S-1-5-18", path)?;
    for index in 0..dacl.len() {
        let entry = dacl
            .ace(index)
            .map_err(|e| io_error("read installation protection ACE", path, e))?;
        let header = entry.header();
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        let ace = entry
            .allowed()
            .ok_or_else(|| unsafe_path("uninterpretable installation protection ACE", path))?;
        let principal = (&ace.SidStart as *const u32).cast_mut().cast();
        // SAFETY: native SID is embedded in the retained validated ACE.
        if unsafe { IsValidSid(principal) } == 0 {
            return Err(unsafe_path("invalid installation protection SID", path));
        }
        const MUTATE: u32 = 0x10000000
            | 0x40000000
            | windows_sys::Win32::Storage::FileSystem::DELETE
            | windows_sys::Win32::Storage::FileSystem::WRITE_DAC
            | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER
            | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA
            | windows_sys::Win32::Storage::FileSystem::FILE_APPEND_DATA
            | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_EA
            | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES
            | windows_sys::Win32::Storage::FileSystem::FILE_DELETE_CHILD;
        if !equal(principal, user.sid()) && !equal(principal, system.0) && ace.Mask & MUTATE != 0 {
            return Err(unsafe_path(
                "installation DACL permits another native writer",
                path,
            ));
        }
    }
    Ok(())
}
