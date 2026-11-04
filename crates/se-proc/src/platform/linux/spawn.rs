use crate::support::*;
use crate::*;
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    ptr,
};

pub(super) struct Child {
    pub pid: ProcessId,
    pub pin: Option<File>,
    pub events: File,
    pub authorization: Option<File>,
    pub pre_exec: Option<ProcessIdentity>,
    pub root: Option<ProcessIdentity>,
    pub status: Option<ExitStatus>,
    pub protocol: Vec<u8>,
    pub authorized: bool,
    pub deferred: bool,
    pub window_payload: Option<Vec<u8>>,
    pub eof: bool,
}
fn fd(rc: i32, api: &str) -> ProcResult<File> {
    if rc < 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            api,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful native allocation returns one newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(rc) })
}
fn duplicate(file: &File) -> ProcResult<File> {
    // SAFETY: borrowed descriptor is live; F_DUPFD_CLOEXEC returns independent ownership >=3.
    fd(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) },
        "duplicate child descriptor",
    )
}
fn pipe() -> ProcResult<(File, File)> {
    let mut pair = [-1; 2];
    // SAFETY: pair is a valid output for two descriptors; neither is shared yet.
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "pipe2",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful pipe2 gives distinct owned descriptors.
    let read = unsafe { File::from_raw_fd(pair[0]) };
    // SAFETY: pair[1] is the distinct newly owned write end returned by pipe2.
    let write = unsafe { File::from_raw_fd(pair[1]) };
    Ok((duplicate(&read)?, duplicate(&write)?))
}
fn socket() -> ProcResult<(File, File)> {
    let mut pair = [-1; 2];
    // SAFETY: valid two-descriptor output; private inherited channel, no pathname.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } < 0
    {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "authorization socketpair",
            io::Error::last_os_error(),
        ));
    }
    let a = fd(pair[0], "authorization socket")?;
    let b = fd(pair[1], "authorization socket")?;
    Ok((duplicate(&a)?, duplicate(&b)?))
}
pub(super) fn pidfd(pid: ProcessId) -> ProcResult<Option<File>> {
    // SAFETY: numeric process selector, no pointers; flags are reserved zero.
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.0, 0) } as i32;
    if rc >= 0 {
        return fd(rc, "pidfd_open").map(Some);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ENOSYS) {
        return Ok(None);
    }
    Err(native(ProcErrorCode::IdentityUnreadable, "pidfd_open", e))
}
fn cstring(value: &[u8], field: &str) -> ProcResult<CString> {
    CString::new(value).map_err(|_| input(field, "NUL is not permitted"))
}
pub(super) fn begin(spec: LaunchSpec) -> ProcResult<Child> {
    let deferred = matches!(
        spec.window,
        Some(WindowSpec::UnixTerminalWithBackend { .. })
    );
    let terminal = super::terminal::Terminal::prepare(&spec)?;
    let terminal_arguments = terminal.as_ref().map(|window| window.arguments());
    let executable = cstring(spec.executable.as_os_str().as_bytes(), "executable")?;
    let cwd = cstring(spec.cwd.as_os_str().as_bytes(), "cwd")?;
    let mut args = Vec::with_capacity(spec.arguments.len() + 1);
    args.push(executable.clone());
    for arg in &spec.arguments {
        args.push(cstring(arg.as_bytes(), "argument")?);
    }
    let mut env = Vec::with_capacity(spec.environment.entries.len());
    for (key, value) in &spec.environment.entries {
        let mut entry = key.as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        env.push(cstring(&entry, "environment")?);
    }
    let argv: Vec<_> = args
        .iter()
        .map(|a| a.as_ptr())
        .chain(Some(ptr::null()))
        .collect();
    let envp: Vec<_> = env
        .iter()
        .map(|a| a.as_ptr())
        .chain(Some(ptr::null()))
        .collect();
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| native(ProcErrorCode::LaunchFailed, "open null device", e))?;
    let streams = [spec.stdio.stdin, spec.stdio.stdout, spec.stdio.stderr].map(|f| {
        f.map_or_else(
            || duplicate(terminal.as_ref().map_or(&null, |window| &window.slave)),
            |f| duplicate(&f),
        )
    });
    let [stdin, stdout, stderr] = streams;
    let streams = [stdin?, stdout?, stderr?];
    let stream_fds = streams.each_ref().map(AsRawFd::as_raw_fd);
    let console_fds = if deferred {
        [terminal
            .as_ref()
            .ok_or_else(|| input("console backend", "requires a terminal"))?
            .slave
            .as_raw_fd(); 3]
    } else {
        stream_fds
    };
    let (events, error) = pipe()?;
    let (authorization, send) = socket()?;
    let error_fd = error.as_raw_fd();
    let authorization_fd = authorization.as_raw_fd();
    let mut kept = vec![error_fd, authorization_fd];
    if deferred {
        kept.extend_from_slice(&stream_fds);
    }
    if let Some(window) = &terminal {
        kept.push(window.master.as_raw_fd());
    }
    kept.sort_unstable();
    // SAFETY: rlimit is native POD and getrlimit fills both initialized scalar fields.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: valid output pointer, read-only process query before fork.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "getrlimit",
            io::Error::last_os_error(),
        ));
    }
    let fd_limit = limit.rlim_cur.min(i32::MAX as u64) as i32;
    // All allocations, locks, paths, argv/env and descriptors are ready. The
    // child branch below uses only native async-signal-safe operations and _exit.
    // SAFETY: no child-side allocator/lock/unwind runs; only prepared native
    // async-signal-safe calls execute before execve or _exit, as shown below.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "fork tracked root",
            io::Error::last_os_error(),
        ));
    }
    if pid == 0 {
        // SAFETY: fork child has private address space; borrowed arrays remain
        // alive until exec/_exit. No Rust allocator, logging, locks or unwind.
        unsafe {
            let die = |number: i32| -> ! {
                let packet = [
                    b'E',
                    (number & 255) as u8,
                    ((number >> 8) & 255) as u8,
                    ((number >> 16) & 255) as u8,
                    ((number >> 24) & 255) as u8,
                ];
                libc::write(error_fd, packet.as_ptr().cast(), packet.len());
                libc::_exit(127)
            };
            if libc::setsid() < 0 {
                die(*libc::__errno_location());
            }
            for (target, source) in console_fds.iter().enumerate() {
                if libc::dup2(*source, target as i32) < 0 {
                    die(*libc::__errno_location());
                }
            }
            let mut low = 3;
            for high in kept
                .iter()
                .map(|fd| (*fd as u32).saturating_sub(1))
                .chain(Some(u32::MAX))
            {
                if low > high {
                    low = high.saturating_add(2);
                    continue;
                }
                if libc::syscall(libc::SYS_close_range, low, high, 0u32) < 0 {
                    if *libc::__errno_location() != libc::ENOSYS {
                        die(*libc::__errno_location());
                    }
                    for descriptor in 3..fd_limit {
                        if !kept.contains(&descriptor) {
                            libc::close(descriptor);
                        }
                    }
                    break;
                }
                low = high.saturating_add(2);
            }
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            if libc::sigprocmask(libc::SIG_SETMASK, &mask, ptr::null_mut()) < 0 {
                die(*libc::__errno_location());
            }
            for signal in 1..65 {
                if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = libc::SIG_DFL;
                    libc::sigemptyset(&mut action.sa_mask);
                    if libc::sigaction(signal, &action, ptr::null_mut()) < 0
                        && *libc::__errno_location() != libc::EINVAL
                    {
                        die(*libc::__errno_location());
                    }
                }
            }
            if libc::chdir(cwd.as_ptr()) < 0 {
                die(*libc::__errno_location());
            }
            if libc::write(error_fd, b"R".as_ptr().cast(), 1) != 1 {
                libc::_exit(126);
            }
            let mut permit = 0u8;
            loop {
                let n = libc::read(authorization_fd, (&mut permit as *mut u8).cast(), 1);
                if n == 1 && permit == 1 {
                    break;
                }
                if n < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                libc::_exit(126);
            }
            if let (Some(window), Some(arguments)) = (&terminal, &terminal_arguments) {
                let number = window.start(arguments, &envp, error_fd);
                if number != 0 {
                    die(number);
                }
            }
            if deferred {
                let number = super::deferred::start_backend(
                    &stream_fds,
                    executable.as_ptr(),
                    &argv,
                    &envp,
                    error_fd,
                );
                if number != 0 {
                    die(number);
                }
                die(super::deferred::exec_console(
                    authorization_fd,
                    executable.as_ptr(),
                    &envp,
                ));
            }
            libc::execve(executable.as_ptr(), argv.as_ptr(), envp.as_ptr());
            die(*libc::__errno_location());
        }
    }
    // Native child creation is now retained in Child before any fallible query.
    // Post-creation pin/identity/registration errors are handled by the caller's
    // arena, never by discarding this object or killing a numeric PID.
    drop(error);
    drop(authorization);
    drop(streams);
    Ok(Child {
        pid: ProcessId(pid as u32),
        pin: None,
        events,
        authorization: Some(send),
        pre_exec: None,
        root: None,
        status: None,
        protocol: Vec::with_capacity(8),
        authorized: false,
        deferred,
        window_payload: None,
        eof: false,
    })
}
impl Child {
    pub fn arm(&mut self) -> ProcResult<()> {
        // SAFETY: fcntl changes only this pipe's flags, before its reactor registration.
        if unsafe { libc::fcntl(self.events.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "nonblocking exec channel",
                io::Error::last_os_error(),
            ));
        }
        self.pin = pidfd(self.pid)?;
        Ok(())
    }
    pub fn authorize(&mut self) -> ProcResult<()> {
        if self.authorized {
            return Ok(());
        }
        let file = self
            .authorization
            .as_ref()
            .ok_or_else(|| input("exec authorization", "channel already revoked"))?;
        // SAFETY: owned pipe endpoint and one-byte buffer; child cannot have
        // closed it unnoticed because readiness/identity were rechecked by caller.
        // send via write would raise SIGPIPE, so use a socket-free block around
        // this exact write through the helper below.
        // SAFETY: one-byte private socket write, MSG_NOSIGNAL prevents a closed
        // helper from delivering SIGPIPE to the embedding host.
        if unsafe {
            libc::send(
                file.as_raw_fd(),
                b"\x01".as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } != 1
        {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "authorize exec",
                io::Error::last_os_error(),
            ));
        }
        if !self.deferred {
            self.authorization = None;
        }
        self.authorized = true;
        Ok(())
    }
    pub fn drain(&mut self) -> ProcResult<()> {
        let mut data = [0u8; 16];
        loop {
            // SAFETY: live owned pipe and writable bounded buffer, nonblocking.
            let n = unsafe {
                libc::read(
                    self.events.as_raw_fd(),
                    data.as_mut_ptr().cast(),
                    data.len(),
                )
            };
            if n == 0 {
                self.eof = true;
                return Ok(());
            }
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(native(ProcErrorCode::LaunchFailed, "read exec channel", e));
            }
            if self.protocol.len() + n as usize > 8 {
                return Err(input("exec channel", "oversized native reply"));
            }
            self.protocol.extend_from_slice(&data[..n as usize]);
        }
    }
    pub fn peek_status(&mut self) -> ProcResult<Option<ExitStatus>> {
        if let Some(s) = &self.status {
            return Ok(Some(s.clone()));
        }
        // SAFETY: zero initialization is the documented waitid no-event state for this POD output.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: exact unreaped child created by this object. WNOWAIT retains
        // the PID and status, WNOHANG cannot occupy a host worker waiting for exit.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid.0,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ECHILD) {
                return Ok(None);
            }
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "waitid exact child",
                e,
            ));
        }
        // SAFETY: siginfo returned by successful waitid has the SIGCHLD layout.
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        // SAFETY: successful waitid returned a nonzero SIGCHLD record above.
        let number = unsafe { info.si_status() } as u32;
        let status = if info.si_code == libc::CLD_EXITED {
            ExitStatus::Code(number)
        } else {
            ExitStatus::Signal {
                number,
                core_dumped: info.si_code == libc::CLD_DUMPED,
            }
        };
        self.status = Some(status.clone());
        Ok(Some(status))
    }
    pub fn reap(&mut self) -> ProcResult<()> {
        // SAFETY: exact child, never -1; WNOHANG so a contradictory observation
        // becomes a refusal rather than a blocking wait.
        let rc = unsafe { libc::waitpid(self.pid.0 as i32, std::ptr::null_mut(), libc::WNOHANG) };
        if rc == 0 {
            return Err(input(
                "reap",
                "owned child still live despite the supplied outside witness",
            ));
        }
        if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD) {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "reap exact child",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
}
