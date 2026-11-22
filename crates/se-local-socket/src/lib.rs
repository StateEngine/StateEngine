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
