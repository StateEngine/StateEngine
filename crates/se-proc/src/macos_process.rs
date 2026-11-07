//! Read-only Darwin observations. A PID is a selector, never signal authority.
use crate::{support::*, *};
use std::{
    ffi::OsString,
    io,
    mem::{size_of, zeroed},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    time::{Duration, Instant},
};

pub(crate) fn bound(deadline: Instant) -> ProcResult<()> {
    if Instant::now() >= deadline {
        return Err(input("process observation", "original deadline elapsed"));
    }
    Ok(())
}

fn unreadable(reason: &str) -> ProcError {
    error(
        ProcErrorCode::IdentityUnreadable,
        ProcErrorDetail::Input {
            field: "Darwin process observation".into(),
            reason: reason.into(),
        },
    )
}

pub(crate) fn info(pid: ProcessId, deadline: Instant) -> ProcResult<Option<libc::proc_bsdinfo>> {
    bound(deadline)?;
    // SAFETY: thread-local errno is cleared so a short/zero native result cannot
    // inherit an unrelated ESRCH and manufacture absence.
    unsafe { *libc::__error() = 0 };
    // SAFETY: the native POD output is initialized and correctly aligned.
    let mut value: libc::proc_bsdinfo = unsafe { zeroed() };
    let wanted = size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: callers validate a positive PID; the exact native output is writable.
    // Nonzero arg includes zombie records, which must remain distinct from absence.
    let count = unsafe {
        libc::proc_pidinfo(
            pid.0 as i32,
            libc::PROC_PIDTBSDINFO,
            1,
            (&mut value as *mut libc::proc_bsdinfo).cast(),
            wanted,
        )
    };
    let cause = io::Error::last_os_error();
    bound(deadline)?;
    if count != wanted {
        if count == 0 && cause.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(if count <= 0 && cause.raw_os_error() != Some(0) {
            native(ProcErrorCode::IdentityUnreadable, "proc_pidinfo", cause)
        } else {
            unreadable("short or empty BSD process result without native absence")
        });
    }
    if value.pbi_pid != pid.0 || value.pbi_start_tvusec >= 1_000_000 {
        return Err(unreadable("invalid native PID or start microseconds"));
    }
    Ok(Some(value))
}

fn state(value: &libc::proc_bsdinfo) -> ProcResult<NativeState> {
    match value.pbi_status {
        libc::SIDL | libc::SRUN | libc::SSLEEP => Ok(NativeState::Running),
        libc::SSTOP => Ok(NativeState::Stopped),
        libc::SZOMB => Ok(NativeState::ExitedAwaitingReap),
        _ => Err(unreadable("unknown native process state")),
    }
}

pub(crate) fn start(value: &libc::proc_bsdinfo) -> StartIdentity {
    StartIdentity::MacOs {
        seconds: value.pbi_start_tvsec,
        // info() validated the native microsecond range before this conversion.
        microseconds: value.pbi_start_tvusec as u32,
    }
}

fn image(pid: ProcessId, deadline: Instant) -> ProcResult<PathBuf> {
    bound(deadline)?;
    let mut bytes = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: clear thread-local errno to preserve a zero result without a cause.
    unsafe { *libc::__error() = 0 };
    // SAFETY: positive validated PID and a bounded initialized byte output.
    let count =
        unsafe { libc::proc_pidpath(pid.0 as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    let cause = io::Error::last_os_error();
    bound(deadline)?;
    if count <= 0 {
        if cause.raw_os_error() == Some(0) {
            return Err(unreadable(
                "empty executable path result without a native cause",
            ));
        }
        return Err(native(
            ProcErrorCode::IdentityUnreadable,
            "proc_pidpath",
            cause,
        ));
    }
    if count as usize >= bytes.len() {
        return Err(capacity("native executable path", bytes.len() as u64));
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| unreadable("unterminated executable path"))?;
    // libproc returns the path length without the trailing NUL.
    if end != count as usize {
        return Err(unreadable("native executable path length mismatch"));
    }
    bytes.truncate(end);
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() {
        return Err(unreadable("native executable path is not absolute"));
    }
    Ok(path)
}

fn absent(pid: ProcessId) -> ProcResult<ProcessRead> {
    Ok(ProcessRead::Absent {
        pid,
        observed_at_unix_ns: now()?,
    })
}

fn exited(pid: ProcessId, boot: BootIdentity, start: StartIdentity) -> ProcResult<ProcessRead> {
    Ok(ProcessRead::ExitedRecord {
        pid,
        boot,
        start,
        state: NativeState::ExitedAwaitingReap,
        // A cold query does not own wait status; zero is not a substitute.
        status: ExitStatus::Unavailable {
            reason: ExitStatusUnavailable::NotOurChild,
        },
        observed_at_unix_ns: now()?,
    })
}

pub fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
    read_process_until(machine, pid, Instant::now() + Duration::from_secs(5))
}

pub fn read_process_until(
    machine: MachineId,
    pid: ProcessId,
    deadline: Instant,
) -> ProcResult<ProcessRead> {
    bound(deadline)?;
    if pid.0 == 0 || pid.0 > i32::MAX as u32 {
        return Err(input("pid", "must be a positive native PID"));
    }
    let boot = crate::owner_probe::macos::boot().map_err(|cause| {
        native(
            ProcErrorCode::IdentityUnreadable,
            cause.operation,
            cause.source,
        )
    })?;
    bound(deadline)?;
    let Some(before) = info(pid, deadline)? else {
        return absent(pid);
    };
    let expected_start = start(&before);
    if state(&before)? == NativeState::ExitedAwaitingReap {
        return exited(pid, boot, expected_start);
    }
    let first_image = image(pid, deadline);
    let Some(after) = info(pid, deadline)? else {
        return absent(pid);
    };
    if start(&after) != expected_start {
        return Err(error(
            ProcErrorCode::IdentityChanged,
            ProcErrorDetail::Identity {
                pid,
                expected_start: Some(expected_start),
                found_start: Some(start(&after)),
                expected: None,
                found: None,
            },
        ));
    }
    if state(&after)? == NativeState::ExitedAwaitingReap {
        return exited(pid, boot, expected_start);
    }
    let first_image = first_image?;
    let final_image = image(pid, deadline);
    let Some(last) = info(pid, deadline)? else {
        return absent(pid);
    };
    if start(&last) != expected_start {
        return Err(error(
            ProcErrorCode::IdentityChanged,
            ProcErrorDetail::Identity {
                pid,
                expected_start: Some(expected_start),
                found_start: Some(start(&last)),
                expected: None,
                found: None,
            },
        ));
    }
    if state(&last)? == NativeState::ExitedAwaitingReap {
        return exited(pid, boot, expected_start);
    }
    let identity = ProcessIdentity {
        machine,
        boot,
        pid,
        start: expected_start,
        image: first_image,
    };
    let final_image = final_image?;
    if identity.image != final_image {
        let mut found = identity.clone();
        found.image = final_image;
        return Err(changed(&identity, Some(&found)));
    }
    bound(deadline)?;
    Ok(ProcessRead::Present(LiveObservation {
        identity,
        state: state(&last)?,
        parent: Some(ProcessId(last.pbi_ppid)),
        observed_at_unix_ns: now()?,
    }))
}

pub(crate) fn exact(expected: &ProcessIdentity, deadline: Instant) -> ProcResult<()> {
    match read_process_until(expected.machine.clone(), expected.pid, deadline)? {
        ProcessRead::Present(live) if live.identity == *expected => Ok(()),
        ProcessRead::Present(live) => Err(changed(expected, Some(&live.identity))),
        ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. } => {
            Err(changed(expected, None))
        }
    }
}
