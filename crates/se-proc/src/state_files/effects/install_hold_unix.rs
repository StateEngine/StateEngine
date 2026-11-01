use crate::state_files::{Result, io_error};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::Path,
    process::Command,
};

pub(super) fn run(
    claim: &File,
    executable: &OsStr,
    args: &[OsString],
    created: Option<&OsStr>,
) -> Result<i32> {
    let path = Path::new(executable);
    // SAFETY: duplicate only this retained claim; CLOEXEC remains set in the
    // holder, and is cleared in the forked child immediately before exec.
    let raw = unsafe { libc::fcntl(claim.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(io_error(
            "duplicate installer claim for child",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl transferred unique ownership of this new descriptor.
    let inherited = unsafe { File::from_raw_fd(raw) };
    let mut command = Command::new(executable);
    command.args(args);
    if let Some(value) = created {
        command.env("SE_INSTALL_CREATED_DIRECTORIES", value);
    }
    // SAFETY: the closure uses only async-signal-safe fcntl and errno access.
    // A duplicated flock shares the same open file description; no explicit
    // unlock is performed when the holder drops its own descriptors.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(raw, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| io_error("start installer under native claim", path, error))?;
    drop(inherited);
    let status = child
        .wait()
        .map_err(|error| io_error("wait for claimed installer", path, error))?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}
