use super::*;
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    ptr,
};

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
fn pipe() -> ProcResult<(File, File)> {
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
        return Err(fail(
            "create bootstrap plan pipe",
            io::Error::last_os_error(),
        ));
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
pub(super) fn spawn(spec: &RuntimeLaunchSpec, frame: Frame) -> ProcResult<Created> {
    let bytes = serde_json::to_vec(&frame).map_err(|e| input("runtime frame", &e.to_string()))?;
    if bytes.len() > MAX_FRAME {
        return Err(capacity("runtime frame bytes", MAX_FRAME as u64));
    }
    let image =
        File::open(&spec.executable).map_err(|e| fail("pin installed runtime executable", e))?;
    if !image
        .metadata()
        .map_err(|e| fail("read installed runtime image", e))?
        .is_file()
    {
        return Err(input(
            "installed runtime executable",
            "regular native executable required",
        ));
    }
    let executable = CString::new(spec.executable.as_os_str().as_bytes())
        .map_err(|_| input("runtime image", "NUL in native path"))?;
    let marker =
        CString::new(ENTRY).map_err(|_| input("runtime entry", "invalid private marker"))?;
    let argv = [
        executable.as_ptr().cast_mut(),
        marker.as_ptr().cast_mut(),
        ptr::null_mut(),
    ];
    let mut environment = Vec::new();
    for (key, value) in &spec.environment.entries {
        let mut bytes = key.as_bytes().to_vec();
        bytes.push(b'=');
        bytes.extend(value.as_bytes());
        environment.push(
            CString::new(bytes).map_err(|_| input("runtime environment", "NUL in native entry"))?,
        );
    }
    let envp: Vec<_> = environment
        .iter()
        .map(|v| v.as_ptr().cast_mut())
        .chain(Some(ptr::null_mut()))
        .collect();
    let (plan_read, plan_write) = pipe()?;
    let mut pair = [-1; 2];
    // SAFETY: exact native output; no path or listener is involved.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            pair.as_mut_ptr(),
        )
    } < 0
    {
        return Err(fail(
            "create bootstrap control socket",
            io::Error::last_os_error(),
        ));
    }
    let parent = owned(pair[0])?;
    let child = owned(pair[1])?;
    let parent = duplicate(&parent)?;
    let child = duplicate(&child)?;
    let enable: i32 = 1;
    // SAFETY: retained receiving socket and exact native integer option value.
    if unsafe {
        libc::setsockopt(
            parent.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enable as *const i32).cast(),
            std::mem::size_of_val(&enable) as u32,
        )
    } < 0
    {
        return Err(fail(
            "enable kernel bootstrap credentials",
            io::Error::last_os_error(),
        ));
    }
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| fail("open runtime null streams", e))?;
    let null = duplicate(&null)?;
    // SAFETY: actions is initialized by the immediately following POSIX call.
    let mut storage: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    // SAFETY: exact writable POSIX action-list storage.
    code(
        // SAFETY: writable native action storage is initialized exactly once.
        unsafe { libc::posix_spawn_file_actions_init(&mut storage) },
        "initialize bootstrap spawn actions",
    )?;
    let mut actions = Actions(storage);
    for (source, target) in [
        (plan_read.as_raw_fd(), 0),
        (null.as_raw_fd(), 1),
        (null.as_raw_fd(), 2),
        (child.as_raw_fd(), 3),
    ] {
        // SAFETY: sources are retained >=10; targets are distinct reserved startup descriptors.
        code(
            // SAFETY: retained source descriptor is duplicated to a distinct reserved startup descriptor.
            unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions.0, source, target) },
            "set exact runtime descriptors",
        )?;
    }
    // SAFETY: close-from action runs only in the spawned executable, preserving 0..3 above.
    code(
        // SAFETY: initialized child action closes only descriptors above the reserved private set.
        unsafe { libc::posix_spawn_file_actions_addclosefrom_np(&mut actions.0, 4) },
        "close unrelated runtime descriptors",
    )?;
    let cgroup = crate::platform::runtime_cgroup()?;
    let authorization = parent
        .try_clone()
        .map_err(|e| fail("duplicate bootstrap authorization", e))?;
    let attributes = spawn_attributes()?;
    let mut pid = 0;
    // SAFETY: native argv/envp are terminated arrays of retained C strings;
    // initialized exact descriptor actions run outside the embedding host.
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            &actions.0,
            &attributes.0,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    code(rc, "posix_spawn installed runtime bootstrap")?;
    // No fallible operation may discard this launched process. All remaining
    // writes and identity reads occur after common code owns this Child.
    Ok(Created {
        native: Child {
            launcher: Some(pid),
            pid: None,
            pin: None,
            image,
        },
        events: parent,
        authorization,
        detachment: RuntimeDetachment::SessionOnly {
            inherited_cgroup: cgroup,
        },
        plan: plan_write,
        encoded: bytes,
        error: None,
    })
}

pub(super) fn receive() -> ProcResult<(Frame, File, File, Instant)> {
    // SAFETY: exact reserved descriptors belong to this private early entry.
    let mut plan = unsafe { File::from_raw_fd(0) };
    // SAFETY: descriptor 3 is the explicit private duplex control descriptor.
    let events = unsafe { File::from_raw_fd(3) };
    let initial = Instant::now() + Duration::from_secs(300);
    let frame: Frame = serde_json::from_slice(&frame_read(&mut plan, initial)?)
        .map_err(|e| input("runtime envelope", &e.to_string()))?;
    let remaining = frame
        .deadline_ms
        .checked_sub(clock()?)
        .filter(|n| *n > 0 && *n <= 300000)
        .ok_or_else(|| input("runtime deadline", "expired or outside the startup bound"))?;
    let deadline = Instant::now() + Duration::from_millis(remaining);
    let mut credentials: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of_val(&credentials) as u32;
    // SAFETY: retained connected socket and correctly sized writable kernel credentials.
    if unsafe {
        libc::getsockopt(
            events.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(fail(
            "authenticate runtime creator",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: immutable current native user read.
    let user = unsafe { libc::geteuid() };
    if length as usize != std::mem::size_of_val(&credentials)
        || credentials.pid as u32 != frame.parent.pid.0
        || credentials.uid != user
    {
        return Err(input(
            "runtime creator",
            "inherited channel does not belong to the exact same-user parent",
        ));
    }
    if let ProcessRead::Present(parent) =
        crate::read_process(frame.parent.machine.clone(), frame.parent.pid)?
    {
        if parent.identity != frame.parent {
            return Err(changed(&frame.parent, Some(&parent.identity)));
        }
    } else {
        return Err(input(
            "runtime creator",
            "parent exited before bootstrap authentication",
        ));
    }
    // Only this executable's early single-threaded entry may fork the final
    // independent runtime. No embedding host/async-runtime thread forks here.
    let count = std::fs::read_dir("/proc/self/task")
        .map_err(|e| fail("inspect bootstrap thread count", e))?
        .try_fold(0usize, |n, entry| entry.map(|_| n + 1))
        .map_err(|e| fail("read bootstrap thread count", e))?;
    if count != 1 {
        return Err(input(
            "runtime private entry",
            "bootstrap must precede every runtime thread",
        ));
    }
    // SAFETY: private early executable is single threaded; setsid has no pointer inputs.
    if unsafe { libc::setsid() } < 0 {
        return Err(fail("detach runtime session", io::Error::last_os_error()));
    }
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| fail("open detached null stream", e))?;
    // SAFETY: replacing this private process's startup stdin with its retained null device.
    if unsafe { libc::dup2(null.as_raw_fd(), 0) } < 0 {
        return Err(fail("detach runtime stdin", io::Error::last_os_error()));
    }
    // Do not drop the old File(0) after dup2: that would close the new descriptor.
    std::mem::forget(plan);
    // SAFETY: private single-threaded native bootstrap; launcher branch only
    // calls _exit. The final child owns this entire unshared Rust state.
    let fork = unsafe { libc::fork() };
    if fork < 0 {
        return Err(fail("fork final runtime", io::Error::last_os_error()));
    }
    if fork > 0 {
        // SAFETY: only the transient launcher exits; final child owns the channels.
        unsafe {
            libc::_exit(0);
        }
    }
    // SAFETY: changes only this private runtime's reserved control descriptor;
    // never let later agent execs inherit the parent-commit channel.
    if unsafe { libc::fcntl(events.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(fail(
            "close runtime channel inheritance",
            io::Error::last_os_error(),
        ));
    }
    let authorization = events
        .try_clone()
        .map_err(|e| fail("duplicate runtime control", e))?;
    Ok((frame, events, authorization, deadline))
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
