//! Observe whether a Windows process belongs to any enclosing Job Object
//! and whether that enclosing job terminates members on close.
use super::*;
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, QueryInformationJobObject,
};

pub(super) fn in_job(process: HANDLE) -> ProcResult<bool> {
    let mut member = 0;
    // SAFETY: retained query-capable process and writable BOOL; null means any job.
    if unsafe { IsProcessInJob(process, ptr::null_mut(), &mut member) } == 0 {
        return Err(last("observe detached runtime job membership"));
    }
    Ok(member != 0)
}

/// Query the current process's enclosing job limits. Passing NULL queries the
/// job associated with the calling process; returns true when
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is active.
pub(in crate::bootstrap) fn enclosing_kill_on_close() -> bool {
    // SAFETY: POD native output buffer initialized to zero.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    let mut returned = 0;
    // SAFETY: NULL job handle queries the calling process's enclosing job with
    // exact struct size and writable output length.
    let ok = unsafe {
        QueryInformationJobObject(
            ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            &mut returned,
        )
    };
    ok != 0 && (info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0
}
