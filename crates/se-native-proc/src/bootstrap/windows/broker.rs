//! Observe whether a Windows process belongs to any enclosing Job Object.
use super::*;
use windows_sys::Win32::System::JobObjects::IsProcessInJob;

pub(super) fn in_job(process: HANDLE) -> ProcResult<bool> {
    let mut member = 0;
    // SAFETY: retained query-capable process and writable BOOL; null means any job.
    if unsafe { IsProcessInJob(process, ptr::null_mut(), &mut member) } == 0 {
        return Err(last("observe detached runtime job membership"));
    }
    Ok(member != 0)
}
