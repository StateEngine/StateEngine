//! Dev-only direct-breakaway probe for Windows fixtures. The shipping
//! product never links this crate; it is a dev-dependency of the test
//! crates only. Fixtures use it to tell whether a job-contained caller can
//! still launch a detached child before they report detached coverage, so a
//! NOT GRADED line always names an actual denial. The probe child is
//! resolved from the environment, joined, and closed before the result
//! returns; no path releases custody without a checked termination and a
//! signalled-handle join.
#![cfg(windows)]
use std::{
    ffi::OsString,
    io,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ACCESS_DENIED, HANDLE, WAIT_OBJECT_0},
    System::{
        JobObjects::IsProcessInJob,
        Threading::{
            CREATE_BREAKAWAY_FROM_JOB, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
            TerminateProcess, WaitForSingleObject,
        },
    },
};
/// Resolves the command interpreter the environment itself names: `COMSPEC`
/// first, then the `SystemRoot` anchor. The probe refuses to guess an
/// installation path when neither is set.
fn interpreter() -> Result<OsString, String> {
    if let Some(comspec) = std::env::var_os("COMSPEC")
        && !comspec.is_empty()
    {
        return Ok(comspec);
    }
    if let Some(root) = std::env::var_os("SystemRoot")
        && !root.is_empty()
    {
        let mut anchored = root;
        anchored.push(r"\System32\cmd.exe");
        return Ok(anchored);
    }
    Err(
        "COMSPEC and SystemRoot are both unset; the probe will not guess an interpreter path"
            .into(),
    )
}
fn in_job(process: HANDLE) -> Result<bool, String> {
    let mut member = 0;
    // SAFETY: a query-capable process handle retained by the caller and a
    // writable BOOL; null job tests every job.
    if unsafe { IsProcessInJob(process, ptr::null_mut(), &mut member) } == 0 {
        return Err(format!(
            "observe probe child job membership: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(member != 0)
}
/// Joins the exact probe child before custody is released. A child that has
/// not exited within its bound gets a checked termination, then a second
/// bounded join; an unconfirmed exit is reported, never dropped silently.
fn ensure_exited(process: &OwnedHandle, deadline: Instant) -> Result<(), String> {
    let bounded = |now: Instant| {
        deadline
            .saturating_duration_since(now)
            .min(Duration::from_secs(10))
            .as_millis()
            .min(u32::MAX as u128) as u32
    };
    // SAFETY: the process handle is valid until its close after the join.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), bounded(Instant::now())) }
        == WAIT_OBJECT_0
    {
        return Ok(());
    }
    let terminated =
        // SAFETY: the handle names this process's exact child.
        unsafe { TerminateProcess(process.as_raw_handle(), 1) } != 0;
    let terminate_fact = if terminated {
        None
    } else {
        Some(io::Error::last_os_error().to_string())
    };
    let join_bound = Duration::from_secs(10).as_millis() as u32;
    // SAFETY: the same retained handle, signalled only on exit.
    let joined =
        unsafe { WaitForSingleObject(process.as_raw_handle(), join_bound) } == WAIT_OBJECT_0;
    if joined {
        return Ok(());
    }
    Err(format!(
        "probe child exit was not confirmed within the bound after termination was {}",
        match terminate_fact {
            None => "issued".into(),
            Some(error) => format!("refused ({error})"),
        }
    ))
}
/// Asks the exact question a launch answers: can this caller break away from
/// its jobs? `Ok(false)` is the one denial a launch maps to `BreakawayDenied`;
/// every other outcome is an error naming the step that failed.
pub fn direct_breakaway_allowed(deadline: Instant) -> Result<bool, String> {
    let interpreter = interpreter()?;
    if !std::path::Path::new(&interpreter).is_file() {
        return Err(format!(
            "resolved interpreter {} does not exist as a file",
            interpreter.to_string_lossy()
        ));
    }
    let mut app: Vec<u16> = interpreter
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut command = OsString::new();
    command.push("\"");
    command.push(&interpreter);
    command.push("\" /d /c exit 0");
    let mut line: Vec<u16> = command.encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: native process output POD starts zeroed; success fills it.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: native startup POD starts zeroed; its size is set below.
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    // SAFETY: writable interpreter, command line, startup and process
    // information; null attributes, environment and working directory
    // inherit the caller's, and no handle is inherited.
    let created = unsafe {
        CreateProcessW(
            app.as_mut_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_BREAKAWAY_FROM_JOB,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut info,
        )
    };
    if created == 0 {
        let cause = io::Error::last_os_error();
        return if cause.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            Ok(false)
        } else {
            Err(format!(
                "direct breakaway probe could not create its child: {cause}"
            ))
        };
    }
    // SAFETY: success returned one owned process and one thread handle.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    // SAFETY: the thread handle came from our successful CreateProcessW.
    let _ = unsafe { CloseHandle(info.hThread) };
    let membership = in_job(process.as_raw_handle());
    // Custody resolves on every path before the handle is released.
    let custody = ensure_exited(&process, deadline);
    match (membership, custody) {
        (Ok(escaped), Ok(())) => Ok(!escaped),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(format!("{first}; custody: {second}")),
    }
}
