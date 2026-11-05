//! macOS native socket custody; the index builder is shared with every platform.
use super::*;
use crate::native_ipc::{IpcIoBound, IpcPeerSide};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
mod limits;
static CHILD_ACTIVE: AtomicBool = AtomicBool::new(false);
struct Lease(bool);
impl Drop for Lease {
    fn drop(&mut self) {
        if self.0 {
            CHILD_ACTIVE.store(false, Ordering::Release);
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    parent: u32,
    birth: se_types::StartIdentity,
    image: se_types::NativePath,
    payload: serde_json::Value,
}
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(2),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
pub struct AtlasWorker {
    child: Child,
    channel: UnixStream,
    stderr: Option<std::process::ChildStderr>,
    tail: super::stderr::StderrTail,
    exit: File,
    deadline: Instant,
    incoming: Vec<u8>,
    reaped: bool,
    peak: u64,
    lease: Lease,
}
impl AtlasWorker {
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
        if CHILD_ACTIVE.swap(true, Ordering::AcqRel) {
            return Err(invalid("previous Atlas child has not been reaped"));
        }
        let lease = Lease(true);
        let peer =
            crate::native_ipc::observe_ipc_self_bounded(&bound()).map_err(io::Error::other)?;
        let envelope = Envelope {
            parent: std::process::id(),
            birth: peer.started().clone(),
            image: peer.image().clone(),
            payload: serde_json::from_slice(payload)
                .map_err(|_| invalid("cold input is not JSON"))?,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(io::Error::other)?;
        if encoded.len() > FRAME_BYTES {
            return Err(invalid("cold envelope exceeds 65536 bytes"));
        }
        let (channel, child_channel) = UnixStream::pair()?;
        channel.set_write_timeout(Some(Duration::from_secs(2)))?;
        let fd = child_channel.as_raw_fd();
        // Prepared before fork: the child executes only native async-safe calls.
        // SAFETY: valid initialized native rlimit output.
        let mut descriptors: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: exact writable native output; no process resources change.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut descriptors) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let close_limit = descriptors.rlim_cur.min(i32::MAX as u64) as i32;
        let parent = std::process::id();
        let mut command = Command::new(image);
        command
            .arg(ENTRY)
            .env_clear()
            .env("LANG", "C.UTF-8")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // SAFETY: captures are scalars prepared before fork; no allocations,
        // locks, logging or unwind run before exec in this native-only closure.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                limits::prepare(parent)?;
                for descriptor in 4..close_limit {
                    // Preserve Command's error pipe until exec: closing it here
                    // would turn an exec failure into an apparent successful spawn.
                    if libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) < 0
                        && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let exit = limits::process_events()?;
        let child = command.spawn()?;
        drop(child_channel);
        let mut worker = Self {
            child,
            channel,
            exit,
            stderr: None,
            tail: super::stderr::StderrTail::new(),
            deadline,
            incoming: Vec::with_capacity(FRAME_BYTES + 4),
            reaped: false,
            peak: 0,
            lease,
        };
        limits::watch(&worker.exit, worker.child.id())?;
        worker.stderr = worker.child.stderr.take();
        let stderr = worker
            .stderr
            .as_ref()
            .ok_or_else(|| invalid("Atlas stderr pipe absent"))?;
        // SAFETY: retained private pipe and process-local descriptor flags.
        if unsafe { libc::fcntl(stderr.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        write_frame(&mut worker.channel, &encoded)?;
        worker.channel.set_nonblocking(true)?;
        Ok(worker)
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn readiness_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.channel.as_fd()
    }
    pub fn wait_ready(&mut self, deadline: Instant) -> io::Result<bool> {
        let mut ready = [
            libc::pollfd {
                fd: self.channel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.exit.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait = deadline
            .min(self.deadline)
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(200) as i32;
        // SAFETY: two retained native descriptors and exact initialized poll outputs.
        let result = unsafe { libc::poll(ready.as_mut_ptr(), ready.len() as libc::nfds_t, wait) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result > 0)
    }
    pub fn peak_observed_bytes(&self) -> u64 {
        self.peak
    }
    pub fn observe_memory(&mut self) -> io::Result<u64> {
        self.peak = self.peak.max(limits::peak(self.child.id())?);
        if self.peak > MEMORY_BYTES {
            self.cancel()?;
            return Err(invalid("Atlas child exceeded 64 MB peak footprint"));
        }
        Ok(self.peak)
    }
    pub fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.drain_stderr()?;
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
                let length = u32::from_le_bytes(
                    self.incoming[..4]
                        .try_into()
                        .map_err(|_| invalid("frame header"))?,
                ) as usize;
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
    pub fn try_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.drain_stderr()?;
            self.reaped = true;
        }
        Ok(status)
    }
    pub fn failure_diagnostic(&mut self) -> io::Result<String> {
        self.drain_stderr()?;
        Ok(self.tail.diagnostic())
    }
    fn drain_stderr(&mut self) -> io::Result<()> {
        let Some(stderr) = &mut self.stderr else {
            return Ok(());
        };
        let mut bytes = [0; 4096];
        let mut consumed = 0;
        while consumed < FRAME_BYTES {
            let length = bytes.len().min(FRAME_BYTES - consumed);
            match stderr.read(&mut bytes[..length]) {
                Ok(0) => break,
                Ok(count) => {
                    consumed += count;
                    self.tail.push(&bytes[..count]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn cancel(&mut self) -> io::Result<()> {
        self.cancel_until(Instant::now() + Duration::from_millis(200))
    }
    /// Keep exact custody until reap or the caller's existing shutdown deadline.
    pub fn cancel_until(&mut self, deadline: Instant) -> io::Result<()> {
        if !self.reaped {
            // An unreaped Child pins this kernel child against PID reuse.
            if self.child.try_wait()?.is_none() {
                self.child.kill()?;
                loop {
                    if self.child.try_wait()?.is_some() {
                        break;
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "Atlas termination pending; retain exact child custody",
                        ));
                    }
                    let mut event = libc::pollfd {
                        fd: self.exit.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let millis = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
                    // SAFETY: one retained child's kqueue and a finite remaining budget.
                    if unsafe { libc::poll(&mut event, 1, millis) } < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
            }
            self.reaped = true;
        }
        Ok(())
    }
}
impl Drop for AtlasWorker {
    fn drop(&mut self) {
        if !self.reaped && self.cancel().is_err() {
            self.lease.0 = false;
        }
    }
}
pub struct WorkerChannel(UnixStream);
impl WorkerChannel {
    pub fn receive() -> io::Result<(Self, Vec<u8>)> {
        // SAFETY: scalar descriptor query; rejects an absent private channel
        // before constructing a BorrowedFd, whose contract requires a live fd.
        if unsafe { libc::fcntl(3, libc::F_GETFD) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Borrow fd 3 to authenticate it before taking ownership; stdin is inert.
        // SAFETY: this single-threaded entry just checked the descriptor is live;
        // nothing closes it before it transfers into the authenticated stream.
        let channel = unsafe { std::os::fd::BorrowedFd::borrow_raw(3) };
        let peer =
            crate::native_ipc::observe_ipc_peer_bounded(channel, IpcPeerSide::Server, &bound())
                .map_err(io::Error::other)?;
        // SAFETY: native current creator query, no mutable storage.
        if peer.pid() != unsafe { libc::getppid() } as u32 {
            return Err(invalid("Atlas channel is not owned by the exact parent"));
        }
        // SAFETY: authenticated inherited socket is transferred exactly once.
        let mut stream = unsafe { UnixStream::from_raw_fd(3) };
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let envelope: Envelope = serde_json::from_slice(&read_frame(&mut stream)?)
            .map_err(|_| invalid("malformed Atlas parent envelope"))?;
        if envelope.parent != peer.pid()
            || &envelope.birth != peer.started()
            || &envelope.image != peer.image()
        {
            return Err(invalid("Atlas parent birth/image differs"));
        }
        limits::restrict()?;
        limits::guard_parent(envelope.parent, &envelope.birth, stream.as_fd())?;
        Ok((
            Self(stream),
            serde_json::to_vec(&envelope.payload).map_err(io::Error::other)?,
        ))
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

pub(super) fn footprint_bytes() -> io::Result<u64> {
    limits::peak(std::process::id())
}
