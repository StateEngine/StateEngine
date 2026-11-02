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
    System::Threading::*,
};

use crate::windows_native::allocation::Allocation;

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
    let descriptor = crate::windows_native::acl::SecurityDescriptor::query(
        job.0,
        SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )
    .map_err(|e| {
        native(
            ProcErrorCode::RecoveryUnproved,
            "read old job protection",
            e,
        )
    })?;
    let current = current_sid()?;
    let control = descriptor.control().map_err(|e| {
        native(
            ProcErrorCode::RecoveryUnproved,
            "read old job DACL control",
            e,
        )
    })?;
    if sid_text(descriptor.owner)? != current || control & SE_DACL_PROTECTED == 0 {
        return Err(input(
            "job security",
            "protected current-user job owner/DACL required",
        ));
    }
    let dacl = descriptor.dacl().ok_or_else(|| {
        input(
            "job security",
            "protected current-user job owner/DACL required",
        )
    })?;
    if dacl.len() != 2 {
        return Err(input("job security", "exact user/SYSTEM job ACL required"));
    }
    let mut seen_user = false;
    let mut seen_system = false;
    for index in 0..dacl.len() {
        let entry = dacl
            .ace(index)
            .map_err(|e| native(ProcErrorCode::RecoveryUnproved, "read old job ACE", e))?;
        let ace = entry
            .allowed()
            .filter(|_| entry.header().AceFlags == 0)
            .ok_or_else(|| input("job security", "unexpected old job ACE"))?;
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
