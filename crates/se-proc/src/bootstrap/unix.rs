//! Shared Unix descriptor isolation, deadline-bounded channel I/O and spawn attributes.
use super::*;
#[cfg(target_os = "macos")]
use std::os::{fd::IntoRawFd, unix::net::UnixStream};
use std::{
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd},
};

pub(in crate::bootstrap) fn fail(api: &str, cause: io::Error) -> ProcError {
    native(ProcErrorCode::LaunchFailed, api, cause)
}
pub(in crate::bootstrap) fn code(rc: i32, api: &str) -> ProcResult<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(fail(api, io::Error::from_raw_os_error(rc)))
    }
}
pub(in crate::bootstrap) fn owned(fd: i32) -> ProcResult<File> {
    if fd < 0 {
        return Err(fail(
            "allocate bootstrap descriptor",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful native allocation transfers one unique descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(in crate::bootstrap) fn duplicate(file: &File) -> ProcResult<File> {
    // SAFETY: borrowed descriptor is retained; new CLOEXEC reference avoids action target descriptors 0..3.
    owned(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) })
}
#[cfg(target_os = "linux")]
pub(in crate::bootstrap) fn socket(operation: &str) -> ProcResult<(File, File)> {
    let mut pair = [-1; 2];
    // SAFETY: exact two-descriptor output; both references become owned on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            pair.as_mut_ptr(),
        )
    } < 0
    {
        return Err(fail(operation, io::Error::last_os_error()));
    }
    let read = owned(pair[0])?;
    let write = owned(pair[1])?;
    Ok((duplicate(&read)?, duplicate(&write)?))
}
#[cfg(target_os = "macos")]
pub(in crate::bootstrap) fn socket(operation: &str) -> ProcResult<(File, File)> {
    let (a, b) = UnixStream::pair().map_err(|e| fail(operation, e))?;
    for stream in [&a, &b] {
        stream
            .set_nonblocking(true)
            .map_err(|e| fail(operation, e))?;
        let enabled: i32 = 1;
        // SAFETY: fresh, retained socket with an exact immutable option value.
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&enabled as *const i32).cast(),
                std::mem::size_of_val(&enabled) as _,
            )
        } < 0
        {
            return Err(fail(operation, std::io::Error::last_os_error()));
        }
    }
    // SAFETY: each unique stream transfers its owned descriptor exactly once.
    let a = unsafe { File::from_raw_fd(a.into_raw_fd()) };
    // SAFETY: independent uniquely owned second socket endpoint.
    let b = unsafe { File::from_raw_fd(b.into_raw_fd()) };
    Ok((duplicate(&a)?, duplicate(&b)?))
}
pub(in crate::bootstrap) struct Actions(pub(in crate::bootstrap) libc::posix_spawn_file_actions_t);
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: this successful initialized action list remains uniquely owned.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}
pub(in crate::bootstrap) struct SpawnAttributes(pub(in crate::bootstrap) libc::posix_spawnattr_t);
impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        // SAFETY: uniquely owned POSIX attributes were successfully initialized.
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}
pub(in crate::bootstrap) fn spawn_attributes() -> ProcResult<SpawnAttributes> {
    // SAFETY: native POD storage is initialized by the immediately following POSIX call.
    let mut value = unsafe { std::mem::zeroed() };
    // SAFETY: exact writable native attribute output storage.
    code(
        // SAFETY: exact writable native attribute storage is initialized once.
        unsafe { libc::posix_spawnattr_init(&mut value) },
        "initialize runtime signal attributes",
    )?;
    let mut attributes = SpawnAttributes(value);
    // SAFETY: sigset_t is POD and both sets are initialized before use.
    let (mut mask, mut defaults): (libc::sigset_t, libc::sigset_t) = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers name exact writable signal-set outputs.
    if unsafe { libc::sigemptyset(&mut mask) } < 0 || unsafe { libc::sigfillset(&mut defaults) } < 0
    {
        return Err(fail(
            "prepare runtime signal sets",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: initialized attributes borrow initialized exact signal-set values.
    code(
        // SAFETY: retained initialized native attributes and empty signal set.
        unsafe { libc::posix_spawnattr_setsigmask(&mut attributes.0, &mask) },
        "reset runtime signal mask",
    )?;
    // SAFETY: same initialized native attributes and default signal set.
    code(
        // SAFETY: retained initialized attributes and complete default signal set.
        unsafe { libc::posix_spawnattr_setsigdefault(&mut attributes.0, &defaults) },
        "reset runtime signal dispositions",
    )?;
    let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
    #[cfg(target_os = "macos")]
    let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
    // SAFETY: literal supported native signal initialization flags.
    code(
        // SAFETY: initialized attributes and literal POSIX signal-reset flags.
        unsafe { libc::posix_spawnattr_setflags(&mut attributes.0, flags as i16) },
        "set runtime signal initialization",
    )?;
    Ok(attributes)
}
pub(in crate::bootstrap) fn clock() -> ProcResult<u64> {
    // SAFETY: timespec is POD; clock_gettime initializes both writable fields.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: correct native clock selector and writable timespec output.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } < 0 {
        return Err(fail("read bootstrap clock", io::Error::last_os_error()));
    }
    Ok((ts.tv_sec as u64).saturating_mul(1000) + ts.tv_nsec as u64 / 1_000_000)
}
pub(in crate::bootstrap) fn wait(file: &File, events: i16, deadline: Instant) -> ProcResult<()> {
    loop {
        check(deadline)?;
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, i32::MAX as u128) as i32;
        // SAFETY: one retained descriptor and initialized exact pollfd output.
        let rc = unsafe { libc::poll(&mut poll, 1, ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(fail("wait bootstrap channel", e));
        }
        if rc > 0 {
            return Ok(());
        }
    }
}
pub(in crate::bootstrap) fn read(
    file: &mut File,
    mut out: &mut [u8],
    deadline: Instant,
) -> ProcResult<()> {
    while !out.is_empty() {
        wait(file, libc::POLLIN, deadline)?;
        match file.read(out) {
            Ok(0) => {
                return Err(input(
                    "runtime startup channel",
                    "EOF before authenticated ownership commit",
                ));
            }
            Ok(n) => out = &mut out[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(e) => return Err(fail("read bootstrap channel", e)),
        }
    }
    Ok(())
}
pub(in crate::bootstrap) fn write(
    file: &mut File,
    mut bytes: &[u8],
    deadline: Instant,
) -> ProcResult<()> {
    while !bytes.is_empty() {
        wait(file, libc::POLLOUT, deadline)?;
        // SAFETY: retained stream socket and borrowed byte extent. Lost
        // children cannot deliver SIGPIPE to the embedding host.
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT;
        #[cfg(target_os = "macos")]
        let flags = libc::MSG_DONTWAIT;
        // SAFETY: retained stream socket and borrowed immutable byte extent.
        let count =
            unsafe { libc::send(file.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), flags) };
        if count > 0 {
            bytes = &bytes[count as usize..];
        } else if count == 0 {
            return Err(input("runtime startup channel", "zero write before commit"));
        } else {
            let cause = io::Error::last_os_error();
            if !matches!(
                cause.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                return Err(fail("write bootstrap channel", cause));
            }
        }
    }
    Ok(())
}

pub(in crate::bootstrap) fn read_diagnostics(
    file: &mut File,
    buffer: &mut [u8],
) -> ProcResult<diagnostics::ReadResult> {
    match file.read(buffer) {
        Ok(0) => Ok(diagnostics::ReadResult::Eof),
        Ok(length) => Ok(diagnostics::ReadResult::Bytes(length)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(diagnostics::ReadResult::Pending)
        }
        Err(error) => Err(fail("read runtime startup stderr", error)),
    }
}

#[cfg(target_os = "linux")]
pub(super) mod linux;
#[cfg(target_os = "macos")]
pub(super) mod macos;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
mod launch;
pub(super) struct Child {
    launcher: Option<libc::pid_t>,
    pid: Option<ProcessId>,
    pin: Option<File>,
    image: File,
    #[cfg(target_os = "macos")]
    exited: std::sync::atomic::AtomicBool,
}

pub(super) fn settle_launcher(child: &mut Child, deadline: Instant) -> ProcResult<()> {
    reap_launcher(child, Some(deadline))
}
fn reap_launcher(child: &mut Child, deadline: Option<Instant>) -> ProcResult<()> {
    while let Some(pid) = child.launcher {
        if let Some(deadline) = deadline {
            check(deadline)?;
        }
        let mut status = 0;
        // SAFETY: exact owned and unreaped direct launcher, never a recorded selector.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(fail("reap runtime launcher", io::Error::last_os_error()));
        }
        if result == pid {
            child.launcher = None;
            if deadline.is_some() && (!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0) {
                return Err(input(
                    "runtime launcher",
                    "transient launcher did not exit successfully",
                ));
            }
        } else if deadline.is_some() {
            std::thread::sleep(Duration::from_millis(1));
        } else {
            return Err(input(
                "runtime launcher",
                "transient launcher has not exited",
            ));
        }
    }
    Ok(())
}

pub(super) fn hello(events: &mut File, deadline: Instant) -> ProcResult<()> {
    write(events, b"R", deadline)
}
pub(super) fn initial_identity(
    _child: &Child,
    _machine: &MachineId,
) -> ProcResult<Option<ProcessIdentity>> {
    Ok(None)
}
pub(super) fn release(child: &mut Child) -> ProcResult<()> {
    reap_launcher(child, None)?;
    child.pin = None;
    Ok(())
}
pub(super) fn revoke(events: &File) -> ProcResult<()> {
    // SAFETY: shut down only this private parent's authorization direction.
    if unsafe { libc::shutdown(events.as_raw_fd(), libc::SHUT_WR) } < 0 {
        return Err(fail(
            "revoke runtime authorization",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}
pub(super) fn verify_image(
    child: &Child,
    path: &std::path::Path,
    identity: &ProcessIdentity,
) -> ProcResult<()> {
    use std::os::unix::fs::MetadataExt;
    let wanted =
        std::fs::canonicalize(path).map_err(|e| fail("resolve installed runtime image", e))?;
    let expected = child
        .image
        .metadata()
        .map_err(|e| fail("read held runtime image", e))?;
    #[cfg(target_os = "linux")]
    let selected = PathBuf::from(format!("/proc/{}/exe", identity.pid.0));
    #[cfg(target_os = "macos")]
    let selected = identity.image.clone();
    let actual = File::open(selected)
        .and_then(|f| f.metadata())
        .map_err(|e| fail("read executed runtime image", e))?;
    // Darwin has pathname pre/post checks, not descriptor execution. Retaining
    // this file must never be described as atomic executable selection there.
    if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) || identity.image != wanted
    {
        return Err(input(
            "runtime image",
            "native child is not the installed executable",
        ));
    }
    #[cfg(target_os = "macos")]
    os::alive(child, identity)?;
    Ok(())
}
