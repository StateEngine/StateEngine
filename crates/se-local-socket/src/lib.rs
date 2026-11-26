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

/// Probe whether `path` is currently accepting local-socket connections and
/// return the OS-verified accepting peer PID when available.
/// Returns `Ok(None)` when no process is listening.
pub async fn probe_peer_pid(path: &Path) -> io::Result<Option<Option<u32>>> {
    #[cfg(unix)]
    let attempt: io::Result<Option<u32>> = match tokio::net::UnixStream::connect(path).await {
        Ok(stream) => Ok(stream
            .peer_cred()
            .ok()
            .and_then(|cred| cred.pid())
            .and_then(|pid| u32::try_from(pid).ok())),
        Err(error) => Err(error),
    };
    #[cfg(windows)]
    let attempt: io::Result<Option<u32>> = {
        use std::os::windows::io::AsRawSocket;
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || {
            uds_windows::UnixStream::connect(path)
                .map(|stream| ready::peer_pid(stream.as_raw_socket()))
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
    };
    match attempt {
        Ok(pid) => Ok(Some(pid)),
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
