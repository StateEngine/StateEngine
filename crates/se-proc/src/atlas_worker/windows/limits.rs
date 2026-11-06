//! Atomically assigned job: one process, fixed memory/CPU and kill on owner exit.
use super::*;
pub(super) fn create() -> io::Result<OwnedHandle> {
    // SAFETY: null name creates an unnamed, noninherited job owned only here.
    let job = owned(
        unsafe { CreateJobObjectW(ptr::null(), ptr::null()) },
        "create Atlas job",
    )?;
    // SAFETY: native all-integer policy POD, filled before its input-only call.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_PRIORITY_CLASS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.BasicLimitInformation.PerProcessUserTimeLimit = 900 * 10_000_000;
    limits.BasicLimitInformation.PriorityClass = IDLE_PRIORITY_CLASS;
    // A working-set reservation requires quota privilege on ordinary Windows
    // accounts. Keep native commit caps; the parent checks the 64 MB resident peak.
    limits.ProcessMemoryLimit = MEMORY_BYTES as usize;
    limits.JobMemoryLimit = MEMORY_BYTES as usize;
    // SAFETY: retained job, exact aligned initialized native policy and size.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
        )
    } == 0
    {
        let source = io::Error::last_os_error();
        return Err(io::Error::new(
            source.kind(),
            format!(
                "SetInformationJobObject(Atlas extended limits, size={}, flags={:#x}, priority={}, working_set={}..{}, process_memory={}, job_memory={}): {source}",
                size_of_val(&limits),
                limits.BasicLimitInformation.LimitFlags,
                limits.BasicLimitInformation.PriorityClass,
                limits.BasicLimitInformation.MinimumWorkingSetSize,
                limits.BasicLimitInformation.MaximumWorkingSetSize,
                limits.ProcessMemoryLimit,
                limits.JobMemoryLimit,
            ),
        ));
    }
    Ok(job)
}
