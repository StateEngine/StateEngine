use super::lease::Lease;
use super::*;
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, ExitStatus, Stdio},
};
pub struct AtlasWorker {
    child: Child,
    channel: UnixStream,
    deadline: Instant,
    incoming: Vec<u8>,
    reaped: bool,
    peak: u64,
    _lease: Lease,
    birth_ticks: u64,
    exit: File,
    diagnostics: super::diagnostics::Diagnostics,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    parent: u32,
    birth: u64,
    image: se_types::NativePath,
    payload: serde_json::Value,
}
fn birth(pid: u32) -> io::Result<u64> {
    let mut bytes = Vec::with_capacity(4096);
    File::open(format!("/proc/{pid}/stat"))?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(invalid("native child stat exceeds bound"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("native stat encoding"))?;
    text.rsplit_once(") ")
        .and_then(|(_, tail)| tail.split_ascii_whitespace().nth(19))
        .ok_or_else(|| invalid("native birth field absent"))?
        .parse()
        .map_err(|_| invalid("native birth malformed"))
}
impl AtlasWorker {
    pub fn wait_ready(&self, deadline: Instant) -> io::Result<bool> {
        let mut fd = libc::pollfd {
            fd: self.channel.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let wait = deadline
            .min(self.deadline)
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(200) as i32;
        // SAFETY: one retained socket and exact writable pollfd output.
        let result = unsafe { libc::poll(&mut fd, 1, wait) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result > 0)
    }
    pub fn readiness_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.channel.as_fd()
    }
    pub fn spawn(image: &Path, payload: &[u8], deadline: Instant) -> io::Result<Self> {
        if !image.is_absolute()
            || payload.len() > FRAME_BYTES
            || deadline <= Instant::now()
            || deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(900)
        {
            return Err(invalid(
                "absolute image, bounded frame and <=15 minute deadline required",
            ));
        }
        let mut lease = Lease::acquire()?;
        let parent = std::process::id();
        let envelope = Envelope {
            parent,
            birth: birth(parent)?,
            image: se_types::NativePath::from_local(std::env::current_exe()?)
                .map_err(|e| invalid(&e.to_string()))?,
            payload: serde_json::from_slice(payload)
                .map_err(|_| invalid("cold input is not JSON"))?,
        };
        let encoded =
            serde_json::to_vec(&envelope).map_err(|_| invalid("cold envelope encoding"))?;
        if encoded.len() > FRAME_BYTES {
            return Err(invalid("cold envelope exceeds 65536 bytes"));
        }
        let (channel, child_channel) = UnixStream::pair()?;
        channel.set_write_timeout(Some(Duration::from_secs(2)))?;
        let fd = child_channel.as_raw_fd();
        let (diagnostics, stderr) = super::diagnostics::Diagnostics::pipe()?;
        let mut command = Command::new(image);
        command
            .arg(ENTRY)
            .env_clear()
            .env("LANG", "C.UTF-8")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        // SAFETY: pre_exec performs only async-signal-safe descriptor/limit calls;
        // all referenced storage is prepared before fork and no locks are taken.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let cap = libc::rlimit {
                    rlim_cur: MEMORY_BYTES,
                    rlim_max: MEMORY_BYTES,
                };
                let cpu = libc::rlimit {
                    rlim_cur: 900,
                    rlim_max: 900,
                };
                let descriptors = libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 64,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &cpu) < 0
                    || libc::setrlimit(libc::RLIMIT_NOFILE, &descriptors) < 0
                    || libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13) < 0
                    || libc::setrlimit(libc::RLIMIT_AS, &cap) < 0
                    || libc::setpriority(libc::PRIO_PROCESS, 0, 10) < 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent as libc::pid_t {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 4u32) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        // SAFETY: immutable exact child PID; pidfd pins this kernel instance.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0u32) } as i32;
        if raw < 0 {
            let original = io::Error::last_os_error();
            let mut child = child;
            let _ = child.kill();
            if child.wait().is_err() {
                lease.retain_on_failed_reap();
            }
            return Err(original);
        }
        // SAFETY: successful pidfd_open transfers one owned descriptor.
        let exit = unsafe { File::from_raw_fd(raw) };
        drop(child_channel);
        let mut worker = Self {
            child,
            channel,
            deadline,
            incoming: Vec::with_capacity(FRAME_BYTES + 4),
            reaped: false,
            peak: 0,
            _lease: lease,
            birth_ticks: 0,
            exit,
            diagnostics,
        };
        worker.birth_ticks = birth(worker.child.id())?;
        write_frame(&mut worker.channel, &encoded)?;
        worker.channel.set_nonblocking(true)?;
        Ok(worker)
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn birth_ticks(&self) -> u64 {
        self.birth_ticks
    }
    pub fn peak_observed_bytes(&self) -> u64 {
        self.peak
    }
    /// Called only after readiness/real progress, not an idle sampling timer.
    pub fn observe_memory(&mut self) -> io::Result<u64> {
        if self.reaped {
            return Ok(self.peak);
        }
        let mut bytes = Vec::with_capacity(8192);
        File::open(format!("/proc/{}/status", self.child.id()))?
            .take(8193)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Err(invalid("child status exceeds bounded observation"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("child status encoding"))?;
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .ok_or_else(|| invalid("child peak RSS unavailable"))?;
        let mut parts = value.split_ascii_whitespace();
        let kib = parts
            .next()
            .ok_or_else(|| invalid("child RSS absent"))?
            .parse::<u64>()
            .map_err(|_| invalid("child RSS malformed"))?;
        if parts.next() != Some("kB") || parts.next().is_some() {
            return Err(invalid("child RSS unit unavailable"));
        }
        self.peak = self.peak.max(
            kib.checked_mul(1024)
                .ok_or_else(|| invalid("child RSS overflow"))?,
        );
        if self.peak > MEMORY_BYTES {
            self.cancel()?;
            return Err(invalid("Atlas child exceeded 64 MB"));
        }
        Ok(self.peak)
    }
    pub fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.diagnostics.drain();
        if Instant::now() >= self.deadline {
            self.cancel()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Atlas cold deadline elapsed",
            ));
        }
        let mut bytes = [0; 4096];
        loop {
            if self.incoming.len() >= 4 {
                let mut header = [0; 4];
                header.copy_from_slice(&self.incoming[..4]);
                let length = u32::from_le_bytes(header) as usize;
                if length > FRAME_BYTES {
                    self.cancel()?;
                    return Err(invalid("malformed Atlas child frame"));
                }
                if self.incoming.len() >= length + 4 {
                    let frame = self.incoming[4..length + 4].to_vec();
                    self.incoming.drain(..length + 4);
                    return Ok(Some(frame));
                }
            }
            let left = (FRAME_BYTES + 4)
                .saturating_sub(self.incoming.len())
                .min(bytes.len());
            if left == 0 {
                self.cancel()?;
                return Err(invalid("Atlas frame buffer exhausted"));
            }
            match self.channel.read(&mut bytes[..left]) {
                Ok(0) => {
                    if !self.incoming.is_empty() {
                        return Err(invalid("truncated Atlas child frame"));
                    }
                    return Ok(None);
                }
                Ok(n) => self.incoming.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
    pub fn acknowledge_completion(&mut self) -> io::Result<()> {
        self.observe_memory()?;
        self.channel.set_nonblocking(false)?;
        self.channel
            .set_write_timeout(Some(Duration::from_millis(200)))?;
        write_frame(&mut self.channel, b"reap")?;
        self.channel.set_nonblocking(true)
    }
    pub fn stderr_report(&mut self) -> String {
        self.diagnostics.report()
    }
    pub fn try_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        self.diagnostics.drain();
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
            self._lease.release();
        }
        Ok(status)
    }
    pub fn cancel(&mut self) -> io::Result<()> {
        if !self.reaped {
            // The unreaped std Child owns this exact kernel child. Its PID
            // cannot be recycled until wait, even if it has already exited.
            if self.child.try_wait()?.is_none() {
                self.child.kill()?;
                let mut event = libc::pollfd {
                    fd: self.exit.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one retained pidfd, exact output and finite grace.
                let ready = unsafe { libc::poll(&mut event, 1, 200) };
                if ready < 0 {
                    return Err(io::Error::last_os_error());
                }
                if self.child.try_wait()?.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Atlas termination pending; retain exact child custody",
                    ));
                }
            }
            self.reaped = true;
            self._lease.release();
        }
        Ok(())
    }
}
impl Drop for AtlasWorker {
    fn drop(&mut self) {
        if !self.reaped && self.cancel().is_err() {
            self._lease.retain_on_failed_reap();
        }
    }
}
pub struct WorkerChannel(UnixStream);
impl WorkerChannel {
    /// The fixed descriptor must be a socket created by the actual parent;
    /// selecting the private marker or supplying a regular stdin grants nothing.
    pub fn receive() -> io::Result<(Self, Vec<u8>)> {
        let mut peer: libc::ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
        // SAFETY: fixed inherited descriptor, exact writable credentials output.
        if unsafe {
            libc::getsockopt(
                3,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: immutable native identity queries, no pointers.
        if peer.pid != unsafe { libc::getppid() } || peer.uid != unsafe { libc::geteuid() } {
            return Err(invalid("Atlas channel is not owned by the exact parent"));
        }
        // SAFETY: successful socket/peer checks establish the uniquely inherited
        // descriptor, transferred once into this private-entry RAII stream.
        let mut stream = unsafe { UnixStream::from_raw_fd(3) };
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let bytes = read_frame(&mut stream)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| invalid("malformed parent envelope"))?;
        if envelope.parent != peer.pid as u32
            || envelope.birth != birth(envelope.parent)?
            || envelope
                .image
                .to_local()
                .map_err(|e| invalid(&e.to_string()))?
                != std::fs::read_link(format!("/proc/{}/exe", peer.pid))?
        {
            return Err(invalid("private channel parent birth/image differs"));
        }
        let bytes =
            serde_json::to_vec(&envelope.payload).map_err(|_| invalid("cold payload encoding"))?;
        super::allocator::configure()?;
        restrict()?;
        Ok((Self(stream), bytes))
    }
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        write_frame(&mut self.0, bytes)
    }
    pub fn await_reap(&mut self) -> io::Result<()> {
        if read_frame(&mut self.0)? != b"reap" {
            return Err(invalid("parent reap acknowledgment absent"));
        }
        Ok(())
    }
}
fn restrict() -> io::Result<()> {
    // This entry has no network or subprocess capability. The inherited socket
    // remains usable; new sockets, connections and descendants are refused.
    #[cfg(target_arch = "x86_64")]
    let architecture = 0xc000003eu32;
    #[cfg(target_arch = "aarch64")]
    let architecture = 0xc00000b7u32;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Atlas syscall containment is unavailable for this architecture",
    ));
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mut filters = vec![
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: architecture,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | libc::EPERM as u32,
        },
    ];
    for syscall in [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_socketpair,
        libc::SYS_clone,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_clone3,
    ] {
        filters.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filters.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | libc::EPERM as u32,
        });
    }
    filters.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    });
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    // SAFETY: one immutable, bounded BPF program retained for both native calls.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
        // SAFETY: the bounded native filter and all its instructions remain live.
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
