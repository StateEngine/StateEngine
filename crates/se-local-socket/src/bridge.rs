//! A Windows AF_UNIX connection as a tokio stream.
use std::{path::Path, sync::Arc, time::Duration};

/// tokio has no Windows AF_UNIX stream, so a connection is bridged to an
/// in-process duplex by two worker threads over one nonblocking socket. They
/// wait on readiness, never a socket timeout, so an idle connection stays
/// valid. Dropping the bridge cancels both: each re-checks within one tick, and
/// the dropped duplex ends any wait on the host side.
pub struct Bridge {
    inner: tokio::io::DuplexStream,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    socket: Arc<uds_windows::UnixStream>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

const BRIDGE_TICK: Duration = Duration::from_millis(250);

impl Drop for Bridge {
    fn drop(&mut self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Release);
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        // Each worker re-checks cancellation at least once per tick, so this
        // join is bounded; it runs off the async runtime.
        let workers = std::mem::take(&mut self.workers);
        let _ = std::thread::Builder::new()
            .name("se-codex-socket-join".into())
            .spawn(move || {
                for worker in workers {
                    let _ = worker.join();
                }
            });
    }
}

impl tokio::io::AsyncRead for Bridge {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Bridge {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) async fn open(path: &Path) -> std::io::Result<Bridge> {
    use std::os::windows::io::AsRawSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    let path = path.to_owned();
    let stream = tokio::task::spawn_blocking(move || uds_windows::UnixStream::connect(path))
        .await
        .map_err(std::io::Error::other)??;
    stream.set_nonblocking(true)?;
    let socket = Arc::new(stream);
    let raw = socket.as_raw_socket();
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (mut from_host, mut to_host) = tokio::io::split(theirs);
    let cancel = Arc::new(AtomicBool::new(false));
    // Wait for readiness one tick at a time; false once cancelled or failed.
    let ready = move |stop: &AtomicBool, write: bool| loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        match super::ready::socket_ready(raw, write, BRIDGE_TICK) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(_) => return false,
        }
    };
    let inbound = tokio::runtime::Handle::current();
    let outbound = inbound.clone();
    let (reader, stop_in) = (Arc::clone(&socket), Arc::clone(&cancel));
    let first = std::thread::Builder::new()
        .name("se-codex-socket-in".into())
        .spawn(move || {
            use std::io::Read;
            use tokio::io::AsyncWriteExt;
            let mut buffer = vec![0_u8; 64 * 1024];
            while ready(&stop_in, false) {
                match (&*reader).read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if inbound
                            .block_on(to_host.write_all(&buffer[..read]))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
            let _ = inbound.block_on(to_host.shutdown());
        })?;
    let (writer, stop_out) = (Arc::clone(&socket), Arc::clone(&cancel));
    let second = std::thread::Builder::new()
        .name("se-codex-socket-out".into())
        .spawn(move || {
            use std::io::Write;
            use tokio::io::AsyncReadExt;
            let mut buffer = vec![0_u8; 64 * 1024];
            'pump: while let Ok(read @ 1..) = outbound.block_on(from_host.read(&mut buffer)) {
                let mut sent = 0;
                while sent < read {
                    if !ready(&stop_out, true) {
                        break 'pump;
                    }
                    match (&*writer).write(&buffer[sent..read]) {
                        Ok(0) => break 'pump,
                        Ok(written) => sent += written,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => break 'pump,
                    }
                }
            }
            // Half-close: the server's last frames still reach the host.
            let _ = writer.shutdown(std::net::Shutdown::Write);
        });
    let second = match second {
        Ok(second) => second,
        Err(error) => {
            // Without its partner the first worker must not outlive this call.
            cancel.store(true, Ordering::Release);
            let _ = socket.shutdown(std::net::Shutdown::Both);
            let _ = first.join();
            return Err(error);
        }
    };
    Ok(Bridge {
        inner: ours,
        cancel,
        socket,
        workers: vec![first, second],
    })
}
