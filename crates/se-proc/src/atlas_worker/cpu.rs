//! Current worker CPU time for cooperative per-file limits.
use std::{io, time::Duration};

#[cfg(target_os = "linux")]
pub fn current_cpu_time() -> io::Result<Duration> {
    // SAFETY: initialized native output for the current process.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: the output is valid and RUSAGE_SELF selects this process only.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let convert = |value: libc::timeval| -> io::Result<Duration> {
        let seconds =
            u64::try_from(value.tv_sec).map_err(|_| io::Error::other("negative CPU seconds"))?;
        let micros = u32::try_from(value.tv_usec)
            .map_err(|_| io::Error::other("invalid CPU microseconds"))?;
        if micros >= 1_000_000 {
            return Err(io::Error::other("invalid CPU microseconds"));
        }
        Ok(Duration::new(seconds, micros * 1000))
    };
    convert(usage.ru_utime)?
        .checked_add(convert(usage.ru_stime)?)
        .ok_or_else(|| io::Error::other("CPU time overflow"))
}

#[cfg(windows)]
pub fn current_cpu_parts_and_thread() -> io::Result<(u64, u64, u32)> {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetCurrentThreadId, GetProcessTimes},
    };
    // SAFETY: each output is an initialized native record.
    let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { std::mem::zeroed() };
    // SAFETY: the current process handle and output pointers are valid.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let micros =
        |t: FILETIME| ((u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)) / 10;
    // SAFETY: retrieving the current thread ID requires no additional preconditions.
    Ok((micros(user), micros(kernel), unsafe {
        GetCurrentThreadId()
    }))
}

#[cfg(target_os = "macos")]
pub fn current_cpu_time() -> io::Result<Duration> {
    // SAFETY: correctly aligned output for the current process and requested version.
    let mut usage: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: valid current PID and writable native resource record.
    if unsafe {
        libc::proc_pid_rusage(
            std::process::id() as i32,
            libc::RUSAGE_INFO_V4,
            (&mut usage as *mut libc::rusage_info_v4).cast(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Duration::from_nanos(
        usage
            .ri_user_time
            .checked_add(usage.ri_system_time)
            .ok_or_else(|| io::Error::other("CPU time overflow"))?,
    ))
}

#[cfg(windows)]
pub fn current_cpu_time() -> io::Result<Duration> {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetProcessTimes},
    };
    // SAFETY: native FILETIME records are valid when zero initialized.
    let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { std::mem::zeroed() };
    // SAFETY: the current-process handle is valid and each output is writable.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    let total = ticks(kernel)
        .checked_add(ticks(user))
        .and_then(|value| value.checked_mul(100))
        .ok_or_else(|| io::Error::other("CPU time overflow"))?;
    Ok(Duration::from_nanos(total))
}
