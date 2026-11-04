use crate::state_files::{Result, io_error, unsafe_path};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::FileTypeExt,
        unix::net::UnixStream,
        unix::process::CommandExt,
    },
    path::Path,
    process::Command,
};

const CLAIM_FD: &str = "SE_INSTALL_CLAIM_FD";
const CUSTODY_FD: &str = "SE_INSTALL_CUSTODY_FD";
const MAX_CUSTODY: usize = 32768;
#[path = "install_child_unix.rs"]
mod child;

pub(super) fn inherited_created_directories() -> Result<Vec<std::path::PathBuf>> {
    let diagnostic = Path::new("inherited installer handoff");
    let descriptor = |name| -> Result<libc::c_int> {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value >= 3)
            .ok_or_else(|| {
                unsafe_path(
                    "installation worker requires a native inherited claim and custody channel",
                    diagnostic,
                )
            })
    };
    let _claim = super::os::inherited_installation_claim(descriptor(CLAIM_FD)?)?;
    // SAFETY: duplicate only the handoff descriptor; an invalid descriptor fails.
    let raw = unsafe { libc::fcntl(descriptor(CUSTODY_FD)?, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(io_error(
            "duplicate native directory custody channel",
            diagnostic,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl transferred this newly allocated descriptor to us.
    let channel = unsafe { File::from_raw_fd(raw) };
    if !channel
        .metadata()
        .map_err(|error| io_error("inspect native custody channel", diagnostic, error))?
        .file_type()
        .is_socket()
    {
        return Err(unsafe_path(
            "native directory custody requires its inherited socket",
            diagnostic,
        ));
    }
    // SAFETY: status operations on our retained descriptor. A forged or
    // incomplete channel must refuse instead of waiting for another writer.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    // SAFETY: preserve existing status flags while making reads nonblocking.
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io_error(
            "configure native custody reader",
            diagnostic,
            io::Error::last_os_error(),
        ));
    }
    let mut bytes = Vec::new();
    channel
        .take((MAX_CUSTODY + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read native directory custody channel", diagnostic, error))?;
    if bytes.len() > MAX_CUSTODY {
        return Err(unsafe_path(
            "native directory custody exceeds 32 KiB",
            diagnostic,
        ));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| unsafe_path("native directory custody is not UTF-8", diagnostic))?;
    let mut paths = Vec::new();
    for line in value.lines() {
        let path = Path::new(line);
        if !path.is_absolute()
            || path.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || line.bytes().any(|byte| byte.is_ascii_control())
            || paths.iter().any(|entry| entry == path)
        {
            return Err(unsafe_path(
                "native directory custody requires unique plain paths",
                diagnostic,
            ));
        }
        paths.push(path.to_owned());
    }
    Ok(paths)
}

pub(super) fn run(
    claim: &File,
    executable: &OsStr,
    args: &[OsString],
    created: Option<&OsStr>,
) -> Result<i32> {
    let path = Path::new(executable);
    let caller = child::caller(path)?;
    let _signals = child::Signals::install(path)?;
    // SAFETY: immutable kernel identity retained for the pre-exec parent check.
    let holder = unsafe { libc::getpid() };
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
    command.process_group(0);
    command.env_remove(CLAIM_FD).env_remove(CUSTODY_FD);
    command.env_remove("SE_INSTALL_CREATED_DIRECTORIES");
    let mut custody = None;
    if let Some(value) = created {
        use std::os::unix::ffi::OsStrExt;
        let bytes = value.as_bytes();
        if bytes.len() > MAX_CUSTODY {
            return Err(unsafe_path("native directory custody exceeds 32 KiB", path));
        }
        let (mut sender, receiver) = UnixStream::pair()
            .map_err(|error| io_error("create native directory custody channel", path, error))?;
        let capacity: libc::c_int = (MAX_CUSTODY * 2) as libc::c_int;
        // SAFETY: retained socket, correctly sized immutable integer option.
        if unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_ref(&capacity).cast(),
                std::mem::size_of_val(&capacity) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io_error(
                "size native custody channel",
                path,
                io::Error::last_os_error(),
            ));
        }
        // Avoid waiting for a child before it exists, even if native socket
        // buffering is smaller than the bounded handoff on this platform.
        sender
            .set_nonblocking(true)
            .map_err(|error| io_error("configure native custody channel", path, error))?;
        sender
            .write_all(bytes)
            .map_err(|error| io_error("publish native directory custody", path, error))?;
        sender
            .shutdown(Shutdown::Write)
            .map_err(|error| io_error("finish native directory custody", path, error))?;
        command.env(CLAIM_FD, raw.to_string());
        command.env(CUSTODY_FD, receiver.as_raw_fd().to_string());
        custody = Some(receiver);
    }
    let custody_raw = custody.as_ref().map(AsRawFd::as_raw_fd);
    // SAFETY: the closure uses only native parent/signal setup, fcntl and errno.
    // A duplicated flock shares the same open file description; no explicit
    // unlock is performed when the holder drops its own descriptors.
    unsafe {
        command.pre_exec(move || {
            child::prepare_worker(holder)?;
            if libc::fcntl(raw, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(channel) = custody_raw
                && libc::fcntl(channel, libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| io_error("start installer under native claim", path, error))?;
    drop(inherited);
    drop(custody);
    child::wait(&mut child, caller, path)
}
