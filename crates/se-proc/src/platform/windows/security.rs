use super::identity::*;
use crate::support::*;
use crate::*;
use std::{
    mem::{size_of, zeroed},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{SystemServices::ACCESS_ALLOWED_ACE_TYPE, Threading::*},
};

struct Allocation(*mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this uniquely owned pointer came from a LocalFree-family security API.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
fn sid_text(sid: PSID) -> ProcResult<String> {
    crate::windows_native::sid_text(sid)
        .map_err(|e| native(ProcErrorCode::ContainmentUnavailable, e.operation, e.source))
}
fn current_sid() -> ProcResult<String> {
    // SAFETY: immutable current-process pseudo handle; shared token code owns its query reference.
    crate::windows_native::process_sid(unsafe { GetCurrentProcess() })
        .map_err(|e| native(ProcErrorCode::ContainmentUnavailable, e.operation, e.source))
}
pub(super) struct Security {
    descriptor: Allocation,
}
impl Security {
    pub fn owner_only() -> ProcResult<Self> {
        let sid = current_sid()?;
        let sddl = wide(std::ffi::OsStr::new(&format!(
            "O:{sid}D:P(A;;GA;;;SY)(A;;GA;;;{sid})"
        )));
        let mut descriptor = ptr::null_mut();
        // SAFETY: retained terminated SDDL and writable native descriptor allocation output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last(
                ProcErrorCode::ContainmentUnavailable,
                "create owner-only job DACL",
            ));
        }
        Ok(Self {
            descriptor: Allocation(descriptor),
        })
    }
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        // SAFETY: SECURITY_ATTRIBUTES is native POD whose optional fields may be zero.
        let mut attributes: SECURITY_ATTRIBUTES = unsafe { zeroed() };
        attributes.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
        attributes.lpSecurityDescriptor = self.descriptor.0;
        attributes.bInheritHandle = 0;
        attributes
    }
}
pub(super) fn verify_job(job: &Handle) -> ProcResult<()> {
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: held READ_CONTROL job and initialized outputs; no policy mutation occurs.
    let status = unsafe {
        GetSecurityInfo(
            job.0,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let allocation = Allocation(descriptor);
    if status != ERROR_SUCCESS {
        return Err(native(
            ProcErrorCode::RecoveryUnproved,
            "read old job protection",
            std::io::Error::from_raw_os_error(status as i32),
        ));
    }
    let current = current_sid()?;
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: retained successful security descriptor and writable control outputs.
    if unsafe { GetSecurityDescriptorControl(allocation.0, &mut control, &mut revision) } == 0 {
        return Err(last(
            ProcErrorCode::RecoveryUnproved,
            "read old job DACL control",
        ));
    }
    // SAFETY: non-null ACL remains inside the successful retained descriptor.
    if sid_text(owner)? != current
        || control & SE_DACL_PROTECTED == 0
        || dacl.is_null()
        // SAFETY: the non-null ACL remains inside the retained native descriptor.
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(input(
            "job security",
            "protected current-user job owner/DACL required",
        ));
    }
    // SAFETY: validated aligned ACL is retained by allocation above.
    let count = unsafe { (*dacl).AceCount };
    if count != 2 {
        return Err(input("job security", "exact user/SYSTEM job ACL required"));
    }
    let mut seen_user = false;
    let mut seen_system = false;
    for index in 0..count {
        let mut raw = ptr::null_mut();
        // SAFETY: valid ACL, in-range index and writable borrowed ACE output.
        if unsafe { GetAce(dacl, u32::from(index), &mut raw) } == 0 {
            return Err(last(ProcErrorCode::RecoveryUnproved, "read old job ACE"));
        }
        // SAFETY: GetAce returns an aligned header within the validated retained ACL.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != 0
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(input("job security", "unexpected old job ACE"));
        }
        // SAFETY: validated allow-ACE type/size supplies its aligned mask and inline SID.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&raw const ace.SidStart).cast_mut().cast())?;
        let full_access = 0x1f003f; // JOB_OBJECT_ALL_ACCESS, excluding reserved bits.
        if ace.Mask != GENERIC_ALL && ace.Mask != full_access {
            return Err(input("job security", "old job access mask changed"));
        }
        if sid == current && !seen_user {
            seen_user = true;
        } else if sid == "S-1-5-18" && !seen_system {
            seen_system = true;
        } else {
            return Err(input(
                "job security",
                "old job grants an unexpected or duplicate principal",
            ));
        }
    }
    if !seen_user || !seen_system {
        return Err(input("job security", "old job user/SYSTEM grants missing"));
    }
    Ok(())
}
