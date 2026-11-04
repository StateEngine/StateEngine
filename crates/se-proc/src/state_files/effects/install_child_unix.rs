//! A public installer caller owns the lifetime of its isolated worker group.
use crate::state_files::{Result, io_error, unsafe_path};
use std::{
    io,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::Child,
    sync::atomic::{AtomicI32, Ordering},
    time::Duration,
};

const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGHUP, libc::SIGTERM];
static CANCELLED: AtomicI32 = AtomicI32::new(0);

extern "C" fn cancel(signal: libc::c_int) {
    let _ = CANCELLED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

/// The dedicated synchronous installer holder must survive cancellation long
/// enough to reap its isolated worker group before releasing the native claim.
pub(super) struct Signals {
    saved: Vec<(libc::c_int, libc::sigaction)>,
}
impl Signals {
    pub(super) fn install(path: &Path) -> Result<Self> {
        CANCELLED.store(0, Ordering::Relaxed);
        let mut guard = Self { saved: Vec::new() };
        for signal in SIGNALS {
            // SAFETY: zero initializes native action storage, then all action
            // fields used by sigaction are set before registration.
            let (mut action, mut previous): (libc::sigaction, libc::sigaction) =
                unsafe { std::mem::zeroed() };
            action.sa_sigaction = cancel as *const () as usize;
            // SAFETY: valid action storage and an async-signal-safe handler
            // that only records a lock-free atomic integer.
            if unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, &mut previous)
            } < 0
            {
                return Err(io_error(
                    "watch installer cancellation",
                    path,
                    io::Error::last_os_error(),
                ));
            }
            guard.saved.push((signal, previous));
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, action) in self.saved.iter().rev() {
            // SAFETY: restore the exact disposition retained by this guard.
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
    }
}

/// Called only in Command's pre-exec child, using native operations and errno.
pub(super) fn prepare_worker(holder: libc::pid_t) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: configure only this forked worker. A holder lost before or
        // during registration is caught by the following kernel parent check.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: read the current kernel parent; no lookup of a reusable PID.
    if unsafe { libc::getppid() } != holder {
        return Err(io::Error::from_raw_os_error(libc::ECHILD));
    }
    for signal in SIGNALS {
        // SAFETY: native action storage is initialized before use.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        // SAFETY: reset inherited holder handlers in this forked worker only.
        if unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut())
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) fn caller(path: &Path) -> Result<libc::pid_t> {
    // SAFETY: immutable kernel observation of this process's actual parent.
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(unsafe_path("installer caller is absent", path));
    }
    Ok(parent)
}

pub(super) fn wait(child: &mut Child, caller: libc::pid_t, path: &Path) -> Result<i32> {
    loop {
        let signal = CANCELLED.load(Ordering::Relaxed);
        // SAFETY: the live parent relation comes from the kernel, not a PID lookup.
        // Reparenting cannot mistake a reused former caller PID for this parent.
        if signal != 0 || unsafe { libc::getppid() } != caller {
            let group = libc::pid_t::try_from(child.id())
                .map_err(|_| unsafe_path("installer worker PID exceeds native range", path))?;
            // SAFETY: Command::process_group(0) created this group. Its original
            // leader is still our unreaped child, so the group ID cannot be reused.
            // Signal only that owned group, including its inherited claim handles.
            if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(io_error("stop abandoned installer group", path, error));
                }
            }
            child
                .wait()
                .map_err(|error| io_error("reap abandoned installer", path, error))?;
            if signal != 0 {
                return Ok(128 + signal);
            }
            return Err(unsafe_path(
                "installer caller exited; worker group stopped; preserve any reported partial installation for recovery",
                path,
            ));
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| io_error("observe claimed installer", path, error))?
        {
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
