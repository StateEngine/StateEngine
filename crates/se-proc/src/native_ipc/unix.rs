#[cfg(target_os = "linux")]
use super::linux as process;
#[cfg(target_os = "macos")]
use super::macos as process;
use super::*;
use std::{
    fs::{self, File},
    io::{Read, Write},
    mem::{size_of, zeroed},
    os::{
        fd::{AsFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::PathBuf,
    time::Duration,
};

fn private_directory(path: &Path) -> IpcNativeResult<File> {
    let pin = crate::state_files::pin_owned_directory(path)
        .map_err(|e| error("pin protected IPC directory", io::Error::other(e)))?;
    let meta = pin
        .metadata()
        .map_err(|e| error("read IPC directory mode", e))?;
    if meta.mode() & 0o777 != 0o700 {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC directory must be mode 0700",
        ));
    }
    Ok(pin)
}

fn stamp(file: &File) -> IpcNativeResult<(u64, u64)> {
    let m = file
        .metadata()
        .map_err(|e| error("read IPC directory identity", e))?;
    Ok((m.dev(), m.ino()))
}
fn socket_stamp(path: &Path) -> IpcNativeResult<(u64, u64)> {
    let m = fs::symlink_metadata(path).map_err(|e| error("read IPC socket identity", e))?;
    if !m.file_type().is_socket()
        || m.mode() & 0o777 != 0o600
        || m.uid() != unsafe { libc::geteuid() }
    {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC socket must be current-owner mode 0600",
        ));
    }
    Ok((m.dev(), m.ino()))
}
pub struct NativeUnixEndpoint {
    listener: UnixListener,
    path: PathBuf,
    directory: File,
    socket: (u64, u64),
}
impl NativeUnixEndpoint {
    /// The existing parent must be protected. A collision is never unlinked or
    /// treated as a stale listener; the runtime lease owner resolves it.
    pub fn bind(path: &Path) -> IpcNativeResult<Self> {
        let parent = path.parent().ok_or_else(|| {
            refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC socket parent required",
            )
        })?;
        let directory = private_directory(parent)?;
        let listener =
            UnixListener::bind(path).map_err(|e| error("bind owner-only IPC socket", e))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| error("protect IPC socket", e))?;
        let socket = socket_stamp(path)?;
        if stamp(&private_directory(parent)?)? != stamp(&directory)? {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "IPC directory changed during bind",
            ));
        }
        listener
            .set_nonblocking(true)
            .map_err(|e| error("make IPC listener nonblocking", e))?;
        Ok(Self {
            listener,
            path: path.to_owned(),
            directory,
            socket,
        })
    }
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }
    /// Clone only a descriptor for registration in the supplied host reactor;
    /// this endpoint retains the directory/socket custody until close.
    pub fn reactor_listener(&self) -> IpcNativeResult<UnixListener> {
        self.listener
            .try_clone()
            .map_err(|e| error("duplicate IPC listener for reactor", e))
    }
    pub fn accept(&self, bound: IpcIoBound) -> IpcNativeResult<NativeUnixStream> {
        loop {
            bound
                .remaining()
                .map_err(|e| error("accept IPC deadline", e))?;
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|e| error("configure accepted IPC stream", e))?;
                    peer(stream.as_fd(), &bound)?;
                    return Ok(NativeUnixStream { stream, bound });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(error("accept IPC client", e)),
            }
        }
    }
    /// Caller first joins every reactor clone/connection. A replaced socket or
    /// directory refuses removal, preserving the replacement and its cause.
    pub fn close(self) -> IpcNativeResult<()> {
        let parent = self.path.parent().ok_or_else(|| {
            refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC socket parent required",
            )
        })?;
        if stamp(&private_directory(parent)?)? != stamp(&self.directory)?
            || socket_stamp(&self.path)? != self.socket
        {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "IPC socket or parent changed before removal",
            ));
        }
        fs::remove_file(&self.path).map_err(|e| error("remove exact owned IPC socket", e))
    }
}
pub struct NativeUnixStream {
    stream: UnixStream,
    bound: IpcIoBound,
}
impl NativeUnixStream {
    pub fn connect(path: &Path, bound: IpcIoBound) -> IpcNativeResult<Self> {
        let parent = path.parent().ok_or_else(|| {
            refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC socket parent required",
            )
        })?;
        let directory = private_directory(parent)?;
        let before = socket_stamp(path)?;
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: zeroed sockaddr_un is valid storage; AF_UNIX and the exact
        // bounded pathname are initialized before connect sees the pointer.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        if bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err(refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "bounded pathname socket required",
            ));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as _;
        }
        #[cfg(target_os = "macos")]
        {
            address.sun_len = size_of::<libc::sockaddr_un>() as u8;
        }
        #[cfg(target_os = "linux")]
        let flags = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::SOCK_STREAM;
        let raw = unsafe { libc::socket(libc::AF_UNIX, flags, 0) };
        if raw < 0 {
            return Err(last("create IPC client socket"));
        }
        // SAFETY: successful socket allocation transfers unique FD ownership.
        let stream = unsafe { UnixStream::from_raw_fd(raw) };
        // CLOEXEC is set before publication to a caller and never inherited.
        if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(last("protect IPC client descriptor"));
        }
        stream
            .set_nonblocking(true)
            .map_err(|e| error("set IPC connect nonblocking", e))?;
        bound
            .remaining()
            .map_err(|e| error("connect IPC deadline", e))?;
        let rc = unsafe {
            libc::connect(
                raw,
                (&address as *const libc::sockaddr_un).cast(),
                size_of::<libc::sockaddr_un>() as _,
            )
        };
        if rc < 0 {
            let cause = io::Error::last_os_error();
            if !matches!(
                cause.raw_os_error(),
                Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
            ) {
                return Err(error("connect native IPC", cause));
            }
            loop {
                let remaining = bound
                    .remaining()
                    .map_err(|e| error("connect IPC deadline", e))?;
                let mut wait = libc::pollfd {
                    fd: raw,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one live descriptor and stack pollfd for this call.
                let ready =
                    unsafe { libc::poll(&mut wait, 1, remaining.as_millis().clamp(1, 10) as i32) };
                if ready < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error("poll IPC connect", e));
                }
                if ready > 0 {
                    if let Some(e) = stream
                        .take_error()
                        .map_err(|e| error("read IPC connect result", e))?
                    {
                        return Err(error("complete IPC connect", e));
                    }
                    break;
                }
            }
        }
        if stamp(&private_directory(parent)?)? != stamp(&directory)?
            || socket_stamp(path)? != before
        {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "IPC endpoint changed during connection",
            ));
        }
        let (uid, _) = process::credentials(stream.as_fd())?;
        if uid != unsafe { libc::geteuid() } {
            return Err(refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC server is a different native user",
            ));
        }
        stream
            .set_nonblocking(false)
            .map_err(|e| error("configure IPC stream", e))?;
        Ok(Self { stream, bound })
    }
    pub fn set_bound(&mut self, bound: IpcIoBound) {
        self.bound = bound;
    }
    pub fn channel(&self) -> BorrowedIpc<'_> {
        self.stream.as_fd()
    }
}
impl Read for NativeUnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let remaining = self.bound.remaining()?;
            self.stream
                .set_read_timeout(Some(remaining.min(Duration::from_millis(10))))?;
            match self.stream.read(buffer) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}
impl Write for NativeUnixStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let remaining = self.bound.remaining()?;
            self.stream
                .set_write_timeout(Some(remaining.min(Duration::from_millis(10))))?;
            match self.stream.write(buffer) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.bound.remaining()?;
        self.stream.flush()
    }
}
pub(super) fn peer(channel: BorrowedIpc<'_>, bound: &IpcIoBound) -> IpcNativeResult<NativeIpcPeer> {
    let (uid, pid) = process::credentials(channel)?;
    if uid != unsafe { libc::geteuid() } {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC peer is a different native user",
        ));
    }
    process::observe(pid, uid, bound)
}
pub(super) fn self_peer(bound: &IpcIoBound) -> IpcNativeResult<NativeIpcPeer> {
    process::observe(std::process::id(), unsafe { libc::geteuid() }, bound)
}
