//! One transport connection. WebSocket framing runs over the agent's private
//! local socket (AF_UNIX on Windows too), or over stdio; never a TCP fallback.
use super::*;
#[cfg(any(unix, windows))]
use futures_util::{SinkExt, StreamExt};
use std::num::NonZeroU32;
#[cfg(any(unix, windows))]
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message as WsMessage, protocol::WebSocketConfig},
};
#[cfg(unix)]
type Socket = WebSocketStream<tokio::net::UnixStream>;
#[cfg(windows)]
type Socket = WebSocketStream<Bridge>;

pub(super) enum Sender {
    Closed,
    Stdio {
        io: Arc<dyn ProviderIoPlatform>,
        port: Arc<ProviderTransport>,
    },
    #[cfg(any(unix, windows))]
    Socket(futures_util::stream::SplitSink<Socket, WsMessage>),
}
pub(super) enum Receiver {
    Stdio {
        io: Arc<dyn ProviderIoPlatform>,
        port: Arc<ProviderTransport>,
        reader: transport::Reader,
    },
    #[cfg(any(unix, windows))]
    Socket(futures_util::stream::SplitStream<Socket>),
}
pub(super) async fn open(
    io: Arc<dyn ProviderIoPlatform>,
    port: Arc<ProviderTransport>,
    socket: Option<&Path>,
    cx: &CallContext,
) -> Result<(Sender, Receiver)> {
    #[cfg(any(unix, windows))]
    if let Some(path) = socket {
        let until = tokio::time::Instant::now() + cx.timeout;
        let stream = loop {
            match connect_stream(path).await {
                Ok(stream) => break stream,
                // Not listening yet; Windows reports that as WSAENETDOWN.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) || (cfg!(windows) && error.raw_os_error() == Some(10050)) =>
                {
                    if tokio::time::Instant::now() >= until {
                        return Err(se_core::scope::unreadable(
                            "Codex private listener readiness",
                            &error.to_string(),
                        ));
                    }
                    tokio::time::sleep_until(
                        (tokio::time::Instant::now() + Duration::from_millis(25)).min(until),
                    )
                    .await;
                }
                Err(error) => {
                    return Err(se_core::scope::unreadable(
                        "Codex private listener",
                        &error.to_string(),
                    ));
                }
            }
        };
        let config = WebSocketConfig::default()
            .read_buffer_size(16384)
            .write_buffer_size(8192)
            .max_write_buffer_size(wire::MAX_LINE_BYTES + 1024)
            .max_message_size(Some(wire::MAX_LINE_BYTES))
            .max_frame_size(Some(wire::MAX_LINE_BYTES));
        let (socket, _) = tokio::time::timeout_at(
            until,
            tokio_tungstenite::client_async_with_config("ws://localhost/", stream, Some(config)),
        )
        .await
        .map_err(|_| {
            incompatible(
                "private WebSocket handshake timed out",
                "Retry after repairing the owned listener.",
            )
        })?
        .map_err(|e| se_core::scope::unreadable("Codex WebSocket Upgrade", &e.to_string()))?;
        let (write, read) = socket.split();
        return Ok((Sender::Socket(write), Receiver::Socket(read)));
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (socket, cx);
    Ok((
        Sender::Stdio {
            io: io.clone(),
            port: port.clone(),
        },
        Receiver::Stdio {
            io,
            port,
            reader: Default::default(),
        },
    ))
}
impl Sender {
    pub(super) async fn send(&mut self, bytes: Vec<u8>, cx: CallContext) -> Result<()> {
        match self {
            Self::Closed => Err(SeError::invalid(
                "Codex transport",
                "the retained open connection",
            )),
            Self::Stdio { io, port } => transport::write(io.as_ref(), port, bytes, cx).await,
            #[cfg(any(unix, windows))]
            Self::Socket(socket) => {
                let text = std::str::from_utf8(bytes.strip_suffix(b"\n").unwrap_or(&bytes))
                    .map_err(|_| SeError::invalid("Codex request", "a UTF-8 JSON frame"))?;
                tokio::time::timeout(cx.timeout, socket.send(WsMessage::text(text)))
                    .await
                    .map_err(|_| {
                        incompatible(
                            "RPC write deadline; acceptance is unknown",
                            "Retain the original input identity; do not resend blindly.",
                        )
                    })?
                    .map_err(|e| {
                        se_core::scope::unreadable(
                            "Codex RPC write; acceptance is unknown",
                            &e.to_string(),
                        )
                    })
            }
        }
    }
    pub(super) async fn close(&mut self, cx: CallContext) -> Result<()> {
        match self {
            Self::Closed => Ok(()),
            Self::Stdio { io, port } => io.finish_input(port, cx).await,
            #[cfg(any(unix, windows))]
            Self::Socket(socket) => tokio::time::timeout(cx.timeout, socket.close())
                .await
                .map_err(|_| {
                    incompatible(
                        "WebSocket close timed out",
                        "Retain native custody and retry cleanup.",
                    )
                })?
                .map_err(|e| se_core::scope::unreadable("Codex WebSocket close", &e.to_string())),
        }
    }
}
impl Receiver {
    pub(super) async fn next(
        &mut self,
        cx: CallContext,
    ) -> Result<Option<(wire::Message, std::time::Instant)>> {
        match self {
            Self::Stdio { io, port, reader } => match reader.next(io.as_ref(), port, cx).await? {
                Some(message) => Ok(Some((message, reader.observed_at()?))),
                None => Ok(None),
            },
            #[cfg(any(unix, windows))]
            Self::Socket(socket) => loop {
                match tokio::time::timeout(cx.timeout, socket.next())
                    .await
                    .map_err(|_| {
                        incompatible(
                            "WebSocket read timed out",
                            "Inspect the retained provider connection.",
                        )
                    })? {
                    Some(Ok(WsMessage::Text(text))) => {
                        let observed_at = std::time::Instant::now();
                        return wire::decode(text.as_bytes())
                            .map(|message| Some((message, observed_at)));
                    }
                    Some(Ok(WsMessage::Close(_))) | None => return Ok(None),
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                    Some(Ok(_)) => {
                        return Err(SeError::invalid("Codex WebSocket", "JSON text messages"));
                    }
                    Some(Err(error)) => {
                        return Err(se_core::scope::unreadable(
                            "Codex WebSocket read",
                            &error.to_string(),
                        ));
                    }
                }
            },
        }
    }
}
pub(super) async fn drain(
    io: Arc<dyn ProviderIoPlatform>,
    port: Arc<ProviderTransport>,
    stream: ProviderStream,
    generation: se_types::Generation,
) {
    let chunk = NonZeroU32::new(16384).unwrap_or(NonZeroU32::MIN);
    loop {
        match io
            .read(
                &port,
                stream,
                chunk,
                context(generation, Duration::from_secs(86400)),
            )
            .await
        {
            Ok(StreamRead::Bytes(_)) => (),
            _ => return,
        }
    }
}

#[cfg(unix)]
async fn connect_stream(path: &Path) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(path).await
}

/// tokio has no Windows AF_UNIX stream, so a blocking connection is bridged to
/// an in-process duplex by two worker threads. The bridge owns their
/// cancellation: dropping it stops both within one socket timeout, even when a
/// live peer stops reading.
#[cfg(windows)]
pub(super) struct Bridge {
    inner: tokio::io::DuplexStream,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    socket: uds_windows::UnixStream,
    workers: Vec<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
const BRIDGE_TICK: Duration = Duration::from_millis(250);

#[cfg(windows)]
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

#[cfg(windows)]
impl tokio::io::AsyncRead for Bridge {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
async fn connect_stream(path: &Path) -> std::io::Result<Bridge> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let path = path.to_owned();
    let stream = tokio::task::spawn_blocking(move || uds_windows::UnixStream::connect(path))
        .await
        .map_err(std::io::Error::other)??;
    stream.set_read_timeout(Some(BRIDGE_TICK))?;
    stream.set_write_timeout(Some(BRIDGE_TICK))?;
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (mut from_host, mut to_host) = tokio::io::split(theirs);
    let cancel = Arc::new(AtomicBool::new(false));
    let mut reader = stream.try_clone()?;
    let mut writer = stream.try_clone()?;
    let inbound = tokio::runtime::Handle::current();
    let outbound = inbound.clone();
    let stop_in = Arc::clone(&cancel);
    let first = std::thread::Builder::new()
        .name("se-codex-socket-in".into())
        .spawn(move || {
            use std::io::Read;
            use tokio::io::AsyncWriteExt;
            let mut buffer = vec![0_u8; 64 * 1024];
            while !stop_in.load(Ordering::Acquire) {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if inbound
                            .block_on(to_host.write_all(&buffer[..read]))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => break,
                }
            }
            let _ = inbound.block_on(to_host.shutdown());
        })?;
    let stop_out = Arc::clone(&cancel);
    let second = std::thread::Builder::new()
        .name("se-codex-socket-out".into())
        .spawn(move || {
            use std::io::Write;
            use tokio::io::AsyncReadExt;
            let mut buffer = vec![0_u8; 64 * 1024];
            'pump: while let Ok(read @ 1..) = outbound.block_on(from_host.read(&mut buffer)) {
                let mut sent = 0;
                while sent < read {
                    if stop_out.load(Ordering::Acquire) {
                        break 'pump;
                    }
                    match writer.write(&buffer[sent..read]) {
                        Ok(0) => break 'pump,
                        Ok(written) => sent += written,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                            ) => {}
                        Err(_) => break 'pump,
                    }
                }
            }
            let _ = writer.shutdown(std::net::Shutdown::Both);
        });
    let second = match second {
        Ok(second) => second,
        Err(error) => {
            // Without its partner the first worker must not outlive this call.
            cancel.store(true, Ordering::Release);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            let _ = first.join();
            return Err(error);
        }
    };
    Ok(Bridge {
        inner: ours,
        cancel,
        socket: stream,
        workers: vec![first, second],
    })
}
