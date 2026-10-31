//! Owner-only local endpoints and native peer observations. No host/store
//! dependency, authority admission, writer, runtime or Tokio lives here.
use se_types::{NativePath, ProcessInstance, Sha256, StartIdentity};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    io,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_security;
#[cfg(unix)]
pub use unix::{NativeUnixEndpoint, NativeUnixStream};
#[cfg(windows)]
pub use windows::{NativePipeEndpoint, NativePipeReservation, NativePipeStream};
#[cfg(unix)]
pub type BorrowedIpc<'a> = std::os::fd::BorrowedFd<'a>;
#[cfg(windows)]
pub type BorrowedIpc<'a> = std::os::windows::io::BorrowedHandle<'a>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcNativeErrorCode {
    AlreadyExists,
    Unreadable,
    UnsafeEndpoint,
    PeerChanged,
    TimedOut,
    Cancelled,
    Unsupported,
}
#[derive(Debug)]
pub struct IpcNativeError {
    pub code: IpcNativeErrorCode,
    pub operation: &'static str,
    pub source: io::Error,
}
impl std::fmt::Display for IpcNativeError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}: {:?}: {}", self.operation, self.code, self.source)
    }
}
impl std::error::Error for IpcNativeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
pub type IpcNativeResult<T> = std::result::Result<T, IpcNativeError>;
fn error(operation: &'static str, source: io::Error) -> IpcNativeError {
    let code = match source.kind() {
        io::ErrorKind::AlreadyExists | io::ErrorKind::AddrInUse => {
            IpcNativeErrorCode::AlreadyExists
        }
        io::ErrorKind::TimedOut => IpcNativeErrorCode::TimedOut,
        io::ErrorKind::Interrupted => IpcNativeErrorCode::Cancelled,
        _ => IpcNativeErrorCode::Unreadable,
    };
    IpcNativeError {
        code,
        operation,
        source,
    }
}
fn refuse(code: IpcNativeErrorCode, operation: &'static str) -> IpcNativeError {
    IpcNativeError {
        code,
        operation,
        source: io::Error::other(operation),
    }
}
fn last(operation: &'static str) -> IpcNativeError {
    error(operation, io::Error::last_os_error())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcPrincipal {
    Unix { uid: u32 },
    Windows { sid: String },
}
/// Constructed only from the connected channel's kernel peer and a checked
/// process observation. This proves native facts, never application authority.
#[derive(Debug)]
pub struct NativeIpcPeer {
    principal: IpcPrincipal,
    pid: u32,
    started: StartIdentity,
    image: NativePath,
    image_sha256: Sha256,
}
impl NativeIpcPeer {
    pub fn principal(&self) -> &IpcPrincipal {
        &self.principal
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn started(&self) -> &StartIdentity {
        &self.started
    }
    pub fn image(&self) -> &NativePath {
        &self.image
    }
    pub fn image_sha256(&self) -> Sha256 {
        self.image_sha256
    }
    /// Same canonical tuple on the client self observation and server peer
    /// observation; callers cannot insert an identity claimed in wire JSON.
    pub fn binding(&self) -> Vec<u8> {
        let mut bytes = b"se.native.peer/v1".to_vec();
        let mut field = |value: &[u8]| {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value);
        };
        match &self.principal {
            IpcPrincipal::Unix { uid } => {
                field(b"unix");
                field(&uid.to_be_bytes());
            }
            IpcPrincipal::Windows { sid } => {
                field(b"windows");
                field(sid.as_bytes());
            }
        }
        field(&self.pid.to_be_bytes());
        match self.started {
            StartIdentity::Linux { start_ticks } => {
                field(b"linux");
                field(&start_ticks.to_be_bytes());
            }
            StartIdentity::Windows { creation_filetime } => {
                field(b"windows");
                field(&creation_filetime.get().to_be_bytes());
            }
            StartIdentity::Macos {
                start_seconds,
                start_micros,
            } => {
                field(b"macos");
                field(&start_seconds.to_be_bytes());
                field(&start_micros.to_be_bytes());
            }
        }
        field(self.image_sha256.as_bytes());
        bytes
    }
    pub fn verify_instance(
        &self,
        expected: &ProcessInstance,
        image: Sha256,
    ) -> IpcNativeResult<()> {
        let expected = expected.fields();
        if self.pid != expected.pid.get()
            || self.started != expected.started
            || self.image != expected.executable
            || self.image_sha256 != image
        {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "native IPC peer differs from the exact expected server",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub enum IpcPeerSide {
    Client,
    Server,
}
pub fn observe_ipc_peer(
    channel: BorrowedIpc<'_>,
    side: IpcPeerSide,
) -> IpcNativeResult<NativeIpcPeer> {
    #[cfg(unix)]
    {
        let _ = side;
        unix::peer(channel)
    }
    #[cfg(windows)]
    {
        windows::peer(channel, side)
    }
}
pub fn observe_ipc_self() -> IpcNativeResult<NativeIpcPeer> {
    #[cfg(unix)]
    {
        unix::self_peer()
    }
    #[cfg(windows)]
    {
        windows::self_peer()
    }
}
fn hash_image(mut file: std::fs::File) -> IpcNativeResult<Sha256> {
    use std::io::Read;
    let before = file
        .metadata()
        .map_err(|e| error("read pinned image metadata", e))?;
    let mut hasher = Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| error("read pinned peer executable", e))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|e| error("reobserve pinned image metadata", e))?;
    if !before.is_file()
        || before.len() != after.len()
        || before
            .modified()
            .map_err(|e| error("read pinned image modification clock", e))?
            != after
                .modified()
                .map_err(|e| error("reobserve pinned image modification clock", e))?
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "executable changed while hashing its native pin",
        ));
    }
    Ok(Sha256::from_bytes(hasher.finalize().into()))
}
/// Shared native I/O bound; polling never extends the original absolute clock.
#[derive(Clone)]
pub struct IpcIoBound {
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}
impl IpcIoBound {
    fn remaining(&self) -> io::Result<std::time::Duration> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }
}
fn native_path(path: &Path) -> IpcNativeResult<NativePath> {
    NativePath::from_local(path.to_owned()).map_err(|_| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "peer executable is not an absolute native path",
        )
    })
}
