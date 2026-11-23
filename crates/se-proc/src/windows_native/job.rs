//! Low-level Windows Job Object FFI and owner-only DACL primitives.
use super::{Error, acl, allocation::Allocation, last, process_sid, sid_text};
use std::{
    ffi::OsStr,
    mem::{size_of, size_of_val, zeroed},
    os::windows::ffi::OsStrExt,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{JobObjects::*, Threading::GetCurrentProcess},
};

pub(crate) const LIMITS: JOB_OBJECT_LIMIT =
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
pub(crate) const PERSISTENT_LIMITS: JOB_OBJECT_LIMIT = JOB_OBJECT_LIMIT_BREAKAWAY_OK;

pub(crate) const fn expected_limits(persistent: bool) -> JOB_OBJECT_LIMIT {
    if persistent {
        PERSISTENT_LIMITS
    } else {
        LIMITS
    }
}

pub(crate) struct Security {
    descriptor: Allocation,
}

impl Security {
    pub(crate) fn owner_only() -> Result<Self, Error> {
        // SAFETY: immutable current-process pseudo handle; shared token code owns its query reference.
        let sid = process_sid(unsafe { GetCurrentProcess() })?;
        let sddl: Vec<u16> = OsStr::new(&format!("O:{sid}D:P(A;;GA;;;SY)(A;;GA;;;{sid})"))
            .encode_wide()
            .chain(Some(0))
            .collect();
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
            return Err(last("create owner-only job DACL"));
        }
        Ok(Self {
            // SAFETY: the native API returned a unique LocalFree allocation.
            descriptor: unsafe { Allocation::from_raw(descriptor) },
        })
    }

    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        // SAFETY: SECURITY_ATTRIBUTES is native POD whose optional fields may be zero.
        let mut attributes: SECURITY_ATTRIBUTES = unsafe { zeroed() };
        attributes.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
        attributes.lpSecurityDescriptor = self.descriptor.as_ptr();
        attributes.bInheritHandle = 0;
        attributes
    }
}

pub(crate) enum DaclFailure {
    Native(&'static str, std::io::Error),
    Policy(&'static str),
}

/// SAFETY: caller retains the live query/read-control job handle throughout this call.
pub(crate) unsafe fn verify_dacl(job: HANDLE) -> Result<(), DaclFailure> {
    // SAFETY: caller upholds handle validity and READ_CONTROL access.
    let descriptor = unsafe {
        acl::SecurityDescriptor::query(
            job,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        )
    }
    .map_err(|e| DaclFailure::Native("read old job protection", e))?;
    // SAFETY: immutable current-process pseudo handle.
    let current = process_sid(unsafe { GetCurrentProcess() })
        .map_err(|e| DaclFailure::Native(e.operation, e.source))?;
    let control = descriptor
        .control()
        .map_err(|e| DaclFailure::Native("read old job DACL control", e))?;
    let owner =
        sid_text(descriptor.owner).map_err(|e| DaclFailure::Native(e.operation, e.source))?;
    if owner != current || control & SE_DACL_PROTECTED == 0 {
        return Err(DaclFailure::Policy(
            "protected current-user job owner/DACL required",
        ));
    }
    let dacl = descriptor.dacl().ok_or(DaclFailure::Policy(
        "protected current-user job owner/DACL required",
    ))?;
    if dacl.len() != 2 {
        return Err(DaclFailure::Policy("exact user/SYSTEM job ACL required"));
    }
    let (mut seen_user, mut seen_system) = (false, false);
    for index in 0..dacl.len() {
        let entry = dacl
            .ace(index)
            .map_err(|e| DaclFailure::Native("read old job ACE", e))?;
        let ace = entry
            .allowed()
            .filter(|_| entry.header().AceFlags == 0)
            .ok_or(DaclFailure::Policy("unexpected old job ACE"))?;
        let sid = sid_text((&raw const ace.SidStart).cast_mut().cast())
            .map_err(|e| DaclFailure::Native(e.operation, e.source))?;
        let full_access = 0x1f003f; // JOB_OBJECT_ALL_ACCESS, excluding reserved bits.
        if ace.Mask != GENERIC_ALL && ace.Mask != full_access {
            return Err(DaclFailure::Policy("old job access mask changed"));
        }
        if sid == current && !seen_user {
            seen_user = true;
        } else if sid == "S-1-5-18" && !seen_system {
            seen_system = true;
        } else {
            return Err(DaclFailure::Policy(
                "old job grants an unexpected or duplicate principal",
            ));
        }
    }
    if !seen_user || !seen_system {
        return Err(DaclFailure::Policy("old job user/SYSTEM grants missing"));
    }
    Ok(())
}

/// SAFETY: caller retains the live query-capable job handle.
pub(crate) unsafe fn query_limits(
    job: HANDLE,
    operation: &'static str,
) -> Result<JOB_OBJECT_LIMIT, Error> {
    // SAFETY: initialized native POD policy output with all optional fields zero.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    // SAFETY: caller upholds live query-capable job handle.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&info) as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last(operation));
    }
    Ok(info.BasicLimitInformation.LimitFlags)
}

/// SAFETY: caller retains the live job handle with JOB_OBJECT_SET_ATTRIBUTES.
pub(crate) unsafe fn set_limits(job: HANDLE, flags: JOB_OBJECT_LIMIT) -> Result<(), Error> {
    // SAFETY: initialized native POD policy input with all optional fields zero.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    info.BasicLimitInformation.LimitFlags = flags;
    // SAFETY: caller upholds live job handle and exact aligned POD size.
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(last("SetInformationJobObject"));
    }
    Ok(())
}

/// SAFETY: caller retains the live job and IOCP handles.
pub(crate) unsafe fn associate_iocp(
    job: HANDLE,
    port: HANDLE,
    key: usize,
    operation: &'static str,
) -> Result<(), Error> {
    let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: key as *mut _,
        CompletionPort: port,
    };
    // SAFETY: caller upholds live job and IOCP handles.
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectAssociateCompletionPortInformation,
            (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
            size_of_val(&association) as u32,
        )
    } == 0
    {
        return Err(last(operation));
    }
    Ok(())
}

/// SAFETY: caller retains the live job handle with JOB_OBJECT_SET_ATTRIBUTES.
pub(crate) unsafe fn clear_iocp(job: HANDLE) -> Result<(), Error> {
    let clear = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: ptr::null_mut(),
        CompletionPort: ptr::null_mut(),
    };
    // SAFETY: Windows 8+ clears a prior completion port when CompletionPort is null.
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectAssociateCompletionPortInformation,
            (&clear as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
            size_of_val(&clear) as u32,
        )
    } == 0
    {
        return Err(last("clear persistent job IOCP"));
    }
    Ok(())
}

/// SAFETY: caller retains the live query-capable job handle.
pub(crate) unsafe fn active_processes(job: HANDLE, operation: &'static str) -> Result<u32, Error> {
    // SAFETY: initialized native POD accounting output.
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
    // SAFETY: caller upholds live query-capable job handle.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of_val(&accounting) as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last(operation));
    }
    Ok(accounting.ActiveProcesses)
}

/// SAFETY: caller retains live query-capable process and job handles.
pub(crate) unsafe fn is_member(
    process: HANDLE,
    job: HANDLE,
    operation: &'static str,
) -> Result<bool, Error> {
    let mut member = 0;
    // SAFETY: caller upholds live handles and writable BOOL output.
    if unsafe { IsProcessInJob(process, job, &mut member) } == 0 {
        return Err(last(operation));
    }
    Ok(member != 0)
}
