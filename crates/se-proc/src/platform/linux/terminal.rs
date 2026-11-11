//! An xterm viewer for the provider's own controlling PTY. Both processes
//! remain in the reserved group; no terminal broker creates an escaped child.
use crate::{support::*, *};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::ffi::OsStrExt,
};

pub(super) struct Terminal {
    pub master: File,
    pub slave: File,
    executable: CString,
    arguments: Vec<CString>,
    deadline_ns: i128,
    saved: libc::termios,
    retain_viewer: bool,
}
fn descriptor(value: i32, api: &str) -> ProcResult<File> {
    if value < 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            api,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the successful allocation returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(value) })
}
impl Terminal {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn prepare(spec: &LaunchSpec) -> ProcResult<Option<Self>> {
        if spec.mode.is_headless() {
            return Ok(None);
        }
        let Some(
            WindowSpec::UnixTerminal {
                executable,
                adapter: TerminalAdapter::Xterm,
            }
            | WindowSpec::UnixTerminalWithBackend {
                executable,
                adapter: TerminalAdapter::Xterm,
            },
        ) = &spec.window
        else {
            return Err(unsupported("Linux windows require the xterm PTY adapter"));
        };
        if !executable.is_absolute() {
            return Err(input(
                "terminal executable",
                "an absolute native path is required",
            ));
        }
        if !matches!(
            spec.window,
            Some(WindowSpec::UnixTerminalWithBackend { .. })
        ) && (spec.stdio.stdin.is_some()
            || spec.stdio.stdout.is_some()
            || spec.stdio.stderr.is_some())
        {
            return Err(input(
                "window streams",
                "the provider must own its console, without pipe redirections",
            ));
        }
        let executable = CString::new(executable.as_os_str().as_bytes())
            .map_err(|_| input("terminal", "NUL in executable"))?;
        // SAFETY: posix_openpt allocates one private close-on-exec master.
        let master = descriptor(
            unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) },
            "open terminal master",
        )?;
        // SAFETY: both functions operate on our live private PTY master.
        if unsafe {
            libc::grantpt(master.as_raw_fd()) < 0 || libc::unlockpt(master.as_raw_fd()) < 0
        } {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "unlock private PTY",
                io::Error::last_os_error(),
            ));
        }
        let mut name = [0i8; 256];
        // SAFETY: the bounded initialized output has its exact capacity.
        let code = unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) };
        if code != 0 {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "private PTY name",
                io::Error::from_raw_os_error(code),
            ));
        }
        // SAFETY: successful ptsname_r supplies a NUL-terminated name in name.
        let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
        // SAFETY: the prepared native path is NUL terminated and opened without acquiring a controlling tty here.
        let slave = descriptor(
            unsafe {
                libc::open(
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                )
            },
            "open terminal slave",
        )?;
        // SAFETY: termios is POD, and tcgetattr initializes it before use.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: live owned slave descriptor and valid output.
        if unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut saved) } < 0 {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "read terminal settings",
                io::Error::last_os_error(),
            ));
        }
        let mut handshake = saved;
        // Disable echo only while consuming xterm's native WINDOWID handshake.
        handshake.c_lflag &= !libc::ECHO;
        // SAFETY: live slave and initialized settings, before any child exists.
        if unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &handshake) } < 0 {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "set terminal handshake",
                io::Error::last_os_error(),
            ));
        }
        let option = format!("-S{}/{}", name.to_string_lossy(), master.as_raw_fd());
        let arguments = [
            executable.clone(),
            CString::new(option).map_err(|_| input("terminal", "invalid PTY option"))?,
            c"-title".into(),
            c"StateEngine agent".into(),
            c"-geometry".into(),
            c"120x40".into(),
        ];
        // SAFETY: initialized native clock output, read before fork.
        let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: CLOCK_MONOTONIC fills a valid timespec output.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } < 0 {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "terminal deadline",
                io::Error::last_os_error(),
            ));
        }
        let deadline_ns = i128::from(clock.tv_sec) * 1_000_000_000
            + i128::from(clock.tv_nsec)
            + spec
                .deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_nanos()
                .min(i128::MAX as u128) as i128;
        Ok(Some(Self {
            master,
            slave,
            executable,
            arguments: arguments.into(),
            saved,
            deadline_ns,
            // Codex starts its backend before the host polls native exec
            // again; its deferred console keeps the existing permit protocol.
            retain_viewer: !matches!(
                spec.window,
                Some(WindowSpec::UnixTerminalWithBackend { .. })
            ),
        }))
    }
    pub fn arguments(&self) -> Vec<*const libc::c_char> {
        self.arguments
            .iter()
            .map(|value| value.as_ptr())
            .chain(Some(std::ptr::null()))
            .collect()
    }
    /// Called only in the already-authorized fork child. No allocator or lock.
    /// The caller reports an errno on the retained exec channel on failure.
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub unsafe fn start(
        &self,
        arguments: &[*const libc::c_char],
        environment: &[*const libc::c_char],
        error_fd: i32,
        authorization_fd: i32,
    ) -> i32 {
        // SAFETY: all descriptors and pointer arrays are prepared before fork;
        // this branch uses native async-signal-safe calls and never unwinds.
        unsafe {
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return *libc::__errno_location();
            }
            let viewer = libc::fork();
            if viewer < 0 {
                return *libc::__errno_location();
            }
            if viewer == 0 {
                // The viewer must not keep a slave endpoint alive after the
                // provider closes its console. Only its inherited master lives.
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
                if null < 0 {
                    libc::_exit(127);
                }
                for stream in 0..3 {
                    if libc::dup2(null, stream) < 0 {
                        libc::_exit(127);
                    }
                }
                if null > 2 {
                    libc::close(null);
                }
                if libc::fcntl(self.master.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                    libc::_exit(127);
                }
                libc::execve(
                    self.executable.as_ptr(),
                    arguments.as_ptr(),
                    environment.as_ptr(),
                );
                let number = *libc::__errno_location();
                let packet = [
                    b'E',
                    number as u8,
                    (number >> 8) as u8,
                    (number >> 16) as u8,
                    (number >> 24) as u8,
                ];
                libc::write(error_fd, packet.as_ptr().cast(), packet.len());
                libc::_exit(127);
            }
            libc::close(self.master.as_raw_fd());
            // xterm -S writes its mapped window ID to the slave. A successful
            // exec alone cannot claim the viewer opened a usable terminal.
            let mut ready = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            let mut name = [0u8; 128];
            let mut length = 0;
            loop {
                let mut clock: libc::timespec = std::mem::zeroed();
                if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) < 0 {
                    return *libc::__errno_location();
                }
                let remaining = self.deadline_ns
                    - (i128::from(clock.tv_sec) * 1_000_000_000 + i128::from(clock.tv_nsec));
                if remaining <= 0 {
                    return libc::ETIMEDOUT;
                }
                let timeout = ((remaining + 999_999) / 1_000_000).min(i128::from(i32::MAX)) as i32;
                let observed = libc::poll(&mut ready, 1, timeout);
                if observed < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                if observed <= 0 {
                    return libc::ETIMEDOUT;
                }
                let mut byte = 0u8;
                if libc::read(0, (&mut byte as *mut u8).cast(), 1) != 1 {
                    return libc::EIO;
                }
                if byte == b'\n' {
                    break;
                }
                if length == name.len() || !byte.is_ascii_hexdigit() {
                    return libc::EPROTO;
                }
                name[length] = byte;
                length += 1;
            }
            if length == 0 {
                return libc::EPROTO;
            }
            if self.retain_viewer {
                // The private pre-exec channel identifies the viewer we created,
                // rather than teaching later readers to trust an executable name.
                let bytes = (viewer as u32).to_le_bytes();
                let packet = [b'V', bytes[0], bytes[1], bytes[2], bytes[3]];
                if libc::write(error_fd, packet.as_ptr().cast(), packet.len())
                    != packet.len() as isize
                {
                    return libc::EIO;
                }
                // Keep the provider in this trusted helper until its viewer's
                // PID, birth and image have been retained by the native owner.
                let mut permit = 0u8;
                loop {
                    let n = libc::read(authorization_fd, (&mut permit as *mut u8).cast(), 1);
                    if n == 1 && permit == 1 {
                        break;
                    }
                    if n < 0 && *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    return libc::EIO;
                }
            }
            if libc::tcsetattr(0, libc::TCSANOW, &self.saved) < 0 {
                return *libc::__errno_location();
            }
            0
        }
    }
}

/// Retain the native viewer before permitting the helper to exec user code.
pub(super) fn retain_viewer(
    child: &mut super::spawn::Child,
    machine: &MachineId,
    offset: usize,
) -> ProcResult<bool> {
    if child.viewer.is_some() {
        return Ok(true);
    }
    let mut bytes = [0; 4];
    bytes.copy_from_slice(&child.protocol[offset + 1..offset + 5]);
    let pid = ProcessId(u32::from_le_bytes(bytes));
    let ProcessRead::Present(viewer) = super::identity::read_process(machine.clone(), pid)? else {
        return Err(input(
            "terminal viewer",
            "created viewer exited before its identity was retained",
        ));
    };
    if child.viewer_image.as_ref() != Some(&viewer.identity.image) {
        // The viewer may not have reached exec yet. Its parent
        // cannot exec the provider or reap it until our permit.
        return Ok(false);
    }
    if viewer.parent != Some(child.pid) {
        return Err(input(
            "terminal viewer",
            "created viewer changed parent before authorization",
        ));
    }
    let channel = child
        .authorization
        .as_ref()
        .ok_or_else(|| input("terminal viewer", "authorization channel was released"))?;
    // SAFETY: private retained socket and one-byte buffer; no
    // signal or inherited executable name is used as authority.
    if unsafe {
        libc::send(
            channel.as_raw_fd(),
            b"\x01".as_ptr().cast(),
            1,
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    } != 1
    {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "authorize terminal viewer",
            io::Error::last_os_error(),
        ));
    }
    child.viewer = Some(viewer.identity);
    if !child.deferred {
        child.authorization = None;
    }
    Ok(true)
}
