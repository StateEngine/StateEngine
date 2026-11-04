use super::*;
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    ptr,
};

mod launch;
pub(super) use launch::{receive, spawn};

pub(super) struct Child {
    launcher: Option<libc::pid_t>,
    pid: Option<ProcessId>,
    pin: Option<File>,
    image: File,
}
fn fail(api: &str, cause: io::Error) -> ProcError {
    native(ProcErrorCode::LaunchFailed, api, cause)
}
fn code(rc: i32, api: &str) -> ProcResult<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(fail(api, io::Error::from_raw_os_error(rc)))
    }
}
fn owned(fd: i32) -> ProcResult<File> {
    if fd < 0 {
        return Err(fail(
            "allocate bootstrap descriptor",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful native allocation transfers one unique descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn duplicate(file: &File) -> ProcResult<File> {
    // SAFETY: borrowed descriptor is retained; new CLOEXEC reference avoids action target descriptors 0..3.
    owned(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) })
}
fn socket(operation: &str) -> ProcResult<(File, File)> {
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
struct Actions(libc::posix_spawn_file_actions_t);
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: this successful initialized action list remains uniquely owned.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}
struct SpawnAttributes(libc::posix_spawnattr_t);
impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        // SAFETY: uniquely owned POSIX attributes were successfully initialized.
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}
fn spawn_attributes() -> ProcResult<SpawnAttributes> {
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
    // SAFETY: literal supported native signal initialization flags.
    code(
        // SAFETY: initialized attributes and literal POSIX signal-reset flags.
        unsafe {
            libc::posix_spawnattr_setflags(
                &mut attributes.0,
                (libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF) as i16,
            )
        },
        "set runtime signal initialization",
    )?;
    Ok(attributes)
}
pub(super) fn clock() -> ProcResult<u64> {
    // SAFETY: timespec is POD; clock_gettime initializes both writable fields.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: correct native clock selector and writable timespec output.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } < 0 {
        return Err(fail("read bootstrap clock", io::Error::last_os_error()));
    }
    Ok((ts.tv_sec as u64).saturating_mul(1000) + ts.tv_nsec as u64 / 1_000_000)
}
fn wait(file: &File, events: i16, deadline: Instant) -> ProcResult<()> {
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
pub(super) fn read(file: &mut File, mut out: &mut [u8], deadline: Instant) -> ProcResult<()> {
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
pub(super) fn write(file: &mut File, mut bytes: &[u8], deadline: Instant) -> ProcResult<()> {
    while !bytes.is_empty() {
        wait(file, libc::POLLOUT, deadline)?;
        // SAFETY: retained stream socket and borrowed byte extent. Lost
        // children cannot deliver SIGPIPE to the embedding host.
        let count = unsafe {
            libc::send(
                file.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
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

pub(super) fn read_diagnostics(
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
pub(super) fn hello(events: &mut File, deadline: Instant) -> ProcResult<()> {
    write(events, b"R", deadline)
}
pub(super) fn receive_hello(
    child: &mut Child,
    events: &mut File,
    deadline: Instant,
) -> ProcResult<ProcessId> {
    wait(events, libc::POLLIN, deadline)?;
    let mut byte = [0u8; 1];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 16];
    // SAFETY: msghdr is native POD; all used output pointers and capacities follow.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: exact retained socket and aligned writable message/control buffers.
    let count = unsafe {
        libc::recvmsg(
            events.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count != 1 || byte != *b"R" || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err(input(
            "runtime hello",
            "missing, unreadable or truncated kernel-authenticated hello",
        ));
    }
    // SAFETY: successful recvmsg initialized the bounded aligned control region.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(input("runtime hello", "kernel sender credentials absent"));
    }
    // SAFETY: header points inside the validated retained recvmsg control region.
    let expected = unsafe {
        (*header).cmsg_level == libc::SOL_SOCKET
            && (*header).cmsg_type == libc::SCM_CREDENTIALS
            && (*header).cmsg_len
                == libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize
    };
    if !expected {
        return Err(input("runtime hello", "unexpected native control record"));
    }
    // SAFETY: exact SCM_CREDENTIALS length checked; copy avoids alignment assumptions.
    let credentials = unsafe { ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>()) };
    // SAFETY: immutable native current-user query.
    if credentials.pid <= 0 || credentials.uid != unsafe { libc::geteuid() } {
        return Err(input("runtime hello", "different native sender owner"));
    }
    let pid = ProcessId(credentials.pid as u32);
    child.pid = Some(pid);
    Ok(pid)
}
pub(super) fn pin(child: &mut Child, pid: ProcessId) -> ProcResult<()> {
    // SAFETY: kernel-reported sender PID; pidfd_open returns an exact instance reference.
    child.pin = Some(owned(
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid.0, 0) } as i32,
    )?);
    Ok(())
}
pub(super) fn verify_image(
    child: &Child,
    path: &std::path::Path,
    identity: &ProcessIdentity,
) -> ProcResult<()> {
    let wanted =
        std::fs::canonicalize(path).map_err(|e| fail("resolve installed runtime image", e))?;
    use std::os::unix::fs::MetadataExt;
    let expected = child
        .image
        .metadata()
        .map_err(|e| fail("read held runtime image", e))?;
    let actual = File::open(format!("/proc/{}/exe", identity.pid.0))
        .and_then(|f| f.metadata())
        .map_err(|e| fail("read executed runtime image", e))?;
    if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) || identity.image != wanted
    {
        return Err(input(
            "runtime image",
            "native child is not the installed executable",
        ));
    }
    Ok(())
}
pub(super) fn alive(child: &Child, identity: &ProcessIdentity) -> ProcResult<()> {
    let pin = child
        .pin
        .as_ref()
        .ok_or_else(|| input("runtime custody", "native pidfd missing"))?;
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: immutable zero-timeout query on the exact retained native instance.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    if rc != 0 {
        return Err(input(
            "runtime custody",
            "exact child is exited or unreadable",
        ));
    }
    match crate::read_process(identity.machine.clone(), identity.pid)? {
        ProcessRead::Present(live) if &live.identity == identity => Ok(()),
        ProcessRead::Present(live) => Err(changed(identity, Some(&live.identity))),
        _ => Err(changed(identity, None)),
    }
}
pub(super) fn abort(child: &mut Child, _identity: Option<&ProcessIdentity>) -> ProcResult<()> {
    let Some(pin) = &child.pin else {
        // EOF revokes an uncommitted child even before its native hello arrives.
        return Err(input(
            "runtime abort",
            "startup authorization revoked; retain unproved child until its kernel hello/exit can be read",
        ));
    };
    // SAFETY: exact retained pidfd, literal signal, no numeric-PID mutation.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pin.as_raw_fd(),
            libc::SIGKILL,
            ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    } < 0
    {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(fail("abort uncommitted runtime", e));
        }
    }
    Ok(())
}
pub(super) fn witness(
    child: &Child,
    identity: &ProcessIdentity,
) -> ProcResult<RuntimeExitObservation> {
    let pin = child
        .pin
        .as_ref()
        .ok_or_else(|| input("runtime custody", "native pidfd missing"))?;
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: retained pidfd is queried without waiting or mutation.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    if rc < 0 {
        return Err(fail("observe runtime pidfd", io::Error::last_os_error()));
    }
    if rc == 0 {
        return Ok(RuntimeExitObservation::Pending {
            identity: identity.clone(),
        });
    }
    if poll.revents & libc::POLLIN == 0 {
        return Err(input("runtime exit", "unreadable pidfd readiness"));
    }
    Ok(RuntimeExitObservation::Exited(Box::new(
        RuntimeExitWitness {
            identity: identity.clone(),
            evidence: ExitEvidence::KernelHandleSignalled,
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
            observed_at_unix_ns: now()?,
        },
    )))
}
pub(super) fn release(child: &mut Child) -> ProcResult<()> {
    if let Some(pid) = child.launcher {
        let mut status = 0;
        // SAFETY: exact still-owned unreaped direct launcher, never a selector from records.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc < 0 {
            return Err(fail("reap runtime launcher", io::Error::last_os_error()));
        }
        if rc == 0 {
            return Err(input(
                "runtime launcher",
                "transient launcher has not exited",
            ));
        }
        child.launcher = None;
    }
    child.pin = None;
    Ok(())
}

pub(super) fn revoke(events: &File) -> ProcResult<()> {
    // SAFETY: retained private duplex socket; shut down only this parent's
    // authorization direction, including duplicate descriptors.
    if unsafe { libc::shutdown(events.as_raw_fd(), libc::SHUT_WR) } < 0 {
        return Err(fail(
            "revoke runtime authorization",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

pub(super) fn boot_id() -> ProcResult<se_types::BootId> {
    crate::platform::runtime_boot_id()
}

pub(super) fn initial_identity(
    _child: &Child,
    _machine: &MachineId,
) -> ProcResult<Option<ProcessIdentity>> {
    Ok(None)
}
pub(super) fn settle_launcher(child: &mut Child, deadline: Instant) -> ProcResult<()> {
    while let Some(pid) = child.launcher {
        check(deadline)?;
        let mut status = 0;
        // SAFETY: exact unreaped direct launcher owned by this startup.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(fail(
                "reap transient runtime launcher",
                io::Error::last_os_error(),
            ));
        }
        if result == pid {
            child.launcher = None;
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                return Err(input(
                    "runtime launcher",
                    "transient launcher did not exit successfully",
                ));
            }
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}
