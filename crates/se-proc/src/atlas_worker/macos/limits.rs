//! Native macOS CPU/descriptor/I/O policy and a transient parent/footprint guard.
use super::*;
use std::{ffi::c_char, os::fd::BorrowedFd};
unsafe extern "C" {
    fn setiopolicy_np(kind: i32, scope: i32, policy: i32) -> i32;
}
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, error: *mut *mut c_char) -> i32;
    fn sandbox_free_error(error: *mut c_char);
}
/// Runs between fork and exec, using only native async-signal-safe calls.
pub(super) unsafe fn prepare(parent: u32) -> io::Result<()> {
    for (kind, value) in [
        (libc::RLIMIT_CPU, 900),
        (libc::RLIMIT_NOFILE, 64),
        (libc::RLIMIT_RSS, MEMORY_BYTES),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        // SAFETY: valid native resource selector and initialized scalar limit.
        if unsafe { libc::setrlimit(kind, &limit) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // IOPOL_TYPE_DISK=0, PROCESS=0, THROTTLE=3 (Darwin sys/resource.h).
    // SAFETY: process-local native resource policy, no pointers or allocation.
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: native process-local disk priority; scalar selectors only.
    if unsafe { setiopolicy_np(0, 0, 3) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: immutable current creator query after all pre-exec preparation.
    if unsafe { libc::getppid() } as u32 != parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}
pub(super) fn process_events() -> io::Result<File> {
    // SAFETY: kqueue allocates one uniquely owned event descriptor.
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful native allocation transfers exactly one descriptor.
    Ok(unsafe { File::from_raw_fd(raw) })
}
pub(super) fn watch(queue: &File, pid: u32) -> io::Result<()> {
    let change = libc::kevent {
        ident: pid as _,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: retained kqueue and exact initialized input; no event output requested.
    if unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &change,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(super) fn peak(pid: u32) -> io::Result<u64> {
    // SAFETY: exact aligned native POD output for one retained/unreaped process.
    let mut usage: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: documented native version and size-matched aligned writable record.
    if unsafe {
        libc::proc_pid_rusage(
            pid as i32,
            libc::RUSAGE_INFO_V4,
            (&mut usage as *mut libc::rusage_info_v4).cast(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(usage
        .ri_lifetime_max_phys_footprint
        .max(usage.ri_resident_size))
}
pub(super) fn restrict() -> io::Result<()> {
    let mut error = std::ptr::null_mut();
    // No source is executed; deny new network endpoints and every descendant/exec.
    // SAFETY: static terminated Seatbelt policy and writable native error output.
    let result = unsafe {
        sandbox_init(
            c"(version 1)(allow default)(deny network*)(deny process-fork)(deny process-exec)"
                .as_ptr(),
            0,
            &mut error,
        )
    };
    if result != 0 {
        let reason = if error.is_null() {
            "Seatbelt sandbox_init refused without a reason".into()
        } else {
            // SAFETY: sandbox_init returned its owned terminated diagnostic string.
            let text = unsafe { std::ffi::CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: this diagnostic was allocated by sandbox_init, released once.
            unsafe { sandbox_free_error(error) };
            text
        };
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Atlas Seatbelt network/process primitive unavailable: {reason}"),
        ));
    }
    Ok(())
}
pub(super) fn guard_parent(
    parent: u32,
    birth: &se_types::StartIdentity,
    channel: BorrowedFd<'_>,
) -> io::Result<()> {
    let events = process_events()?;
    watch(&events, parent)?;
    let observed =
        crate::native_ipc::observe_ipc_peer_bounded(channel, IpcPeerSide::Server, &bound())
            .map_err(io::Error::other)?;
    if observed.pid() != parent || observed.started() != birth {
        return Err(invalid(
            "Atlas parent changed during exit-watch registration",
        ));
    }
    let timer = libc::kevent {
        ident: 1,
        filter: libc::EVFILT_TIMER,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: 0,
        data: 10,
        udata: std::ptr::null_mut(),
    };
    // The 10 ms guard exists only in this finite, transient cold process.
    // SAFETY: live queue and initialized bounded interval input.
    if unsafe {
        libc::kevent(
            events.as_raw_fd(),
            &timer,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    std::thread::Builder::new()
        .name("atlas-cold-guard".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            // SAFETY: zeroed native POD output for the one retained event queue.
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            loop {
                // SAFETY: retained queue, exact writable event, finite process lifetime.
                let count = unsafe {
                    libc::kevent(
                        events.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        &mut event,
                        1,
                        std::ptr::null(),
                    )
                };
                let reason: Option<&[u8]> = if count < 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    Some(b"Atlas cold native exit/footprint guard became unreadable\n")
                } else if event.filter == libc::EVFILT_PROC {
                    Some(b"Atlas cold parent exited\n")
                } else {
                    match peak(std::process::id()) {
                        Ok(bytes) if bytes > MEMORY_BYTES => {
                            Some(b"Atlas cold 64 MB footprint limit exceeded\n")
                        }
                        Ok(_) => None,
                        Err(_) => Some(b"Atlas cold native footprint observation failed\n"),
                    }
                };
                if let Some(reason) = reason {
                    // SAFETY: fixed diagnostic bytes and immediate exit affect
                    // only this owned worker, never a parent or another user.
                    unsafe {
                        libc::write(2, reason.as_ptr().cast(), reason.len());
                        libc::_exit(122)
                    };
                }
            }
        })?;
    Ok(())
}
