//! One transport connection. WebSocket framing runs over a private Unix socket;
//! Windows uses the documented stock stdio baseline, never a TCP fallback.
use super::*;
#[cfg(unix)]
use futures_util::{SinkExt, StreamExt};
use std::num::NonZeroU32;
#[cfg(unix)]
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message as WsMessage, protocol::WebSocketConfig},
};
#[cfg(unix)]
type Socket = WebSocketStream<tokio::net::UnixStream>;

pub(super) enum Sender {
    Closed,
    Stdio {
        io: Arc<dyn ProviderIoPlatform>,
        port: Arc<ProviderTransport>,
    },
    #[cfg(unix)]
    Socket(futures_util::stream::SplitSink<Socket, WsMessage>),
}
pub(super) enum Receiver {
    Stdio {
        io: Arc<dyn ProviderIoPlatform>,
        port: Arc<ProviderTransport>,
        reader: transport::Reader,
    },
    #[cfg(unix)]
    Socket(futures_util::stream::SplitStream<Socket>),
}
pub(super) async fn open(
    io: Arc<dyn ProviderIoPlatform>,
    port: Arc<ProviderTransport>,
    socket: Option<&Path>,
    cx: &CallContext,
) -> Result<(Sender, Receiver)> {
    #[cfg(unix)]
    if let Some(path) = socket {
        let until = tokio::time::Instant::now() + cx.timeout;
        let stream = loop {
            match tokio::net::UnixStream::connect(path).await {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
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
    #[cfg(not(unix))]
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
            #[cfg(unix)]
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
            #[cfg(unix)]
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
    pub(super) async fn next(&mut self, cx: CallContext) -> Result<Option<wire::Message>> {
        match self {
            Self::Stdio { io, port, reader } => reader.next(io.as_ref(), port, cx).await,
            #[cfg(unix)]
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
                        return wire::decode(text.as_bytes()).map(Some);
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
