//! Local (AF_UNIX) sockets for agent providers: the private forwarder an agent
//! runs as, the identity that lets an owner remove only its own endpoint, and a
//! connection as a tokio stream on every platform.
use std::{io, path::Path};

#[cfg(windows)]
mod bridge;
pub mod forward;
pub mod identity;
#[cfg(windows)]
mod ready;

#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;
/// tokio has no Windows AF_UNIX stream, so a nonblocking socket is bridged.
#[cfg(windows)]
pub use bridge::Bridge as Stream;

/// Connect to a local socket. A socket that is not listening yet reads as
/// `ConnectionRefused` on every platform (Windows reports WSAENETDOWN).
pub async fn connect(path: &Path) -> io::Result<Stream> {
    #[cfg(unix)]
    {
        tokio::net::UnixStream::connect(path).await
    }
    #[cfg(windows)]
    {
        bridge::open(path).await.map_err(|error| {
            if error.raw_os_error() == Some(10050) {
                io::Error::new(io::ErrorKind::ConnectionRefused, error)
            } else {
                error
            }
        })
    }
}

/// OS-verified peer process identity observed on a connected local socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerProcess {
    pub pid: u32,
    /// Windows process creation FILETIME (100ns ticks since 1601-01-01 UTC) when
    /// verified against a live process handle.
    pub birth: Option<u64>,
}

/// Probe whether `path` is currently accepting local-socket connections and
/// return the OS-verified accepting peer identity when available.
/// Returns `Ok(None)` when no process is listening.
pub async fn probe_peer_identity(path: &Path) -> io::Result<Option<Option<PeerProcess>>> {
    #[cfg(unix)]
    let attempt: io::Result<Option<PeerProcess>> = match tokio::net::UnixStream::connect(path).await
    {
        Ok(stream) => Ok(stream
            .peer_cred()
            .ok()
            .and_then(|cred| cred.pid())
            .and_then(|pid| u32::try_from(pid).ok())
            .map(|pid| PeerProcess { pid, birth: None })),
        Err(error) => Err(error),
    };
    #[cfg(windows)]
    let attempt: io::Result<Option<PeerProcess>> = {
        use std::os::windows::io::AsRawSocket;
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || {
            uds_windows::UnixStream::connect(path).map(|stream| {
                ready::peer_identity(stream.as_raw_socket()).map(|(pid, birth)| PeerProcess {
                    pid,
                    birth: Some(birth),
                })
            })
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
    };
    match attempt {
        Ok(peer) => Ok(Some(peer)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) || (cfg!(windows) && error.raw_os_error() == Some(10050)) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
