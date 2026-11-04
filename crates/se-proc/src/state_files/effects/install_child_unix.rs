//! A public installer caller owns the lifetime of its isolated worker group.
use crate::state_files::{Result, io_error, unsafe_path};
use std::{io, os::unix::process::ExitStatusExt, path::Path, process::Child, time::Duration};

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
        // SAFETY: the live parent relation comes from the kernel, not a PID lookup.
        // Reparenting cannot mistake a reused former caller PID for this parent.
        if unsafe { libc::getppid() } != caller {
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
