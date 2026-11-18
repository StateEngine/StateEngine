//! Attach to the stock app-server daemon that owns one login.
//!
//! Codex ships the shared process this design needs: `app-server daemon` holds
//! the login, its pid, its lock and a control socket, and serves each agent as
//! a thread inside it. StateEngine therefore never becomes a second owner of a
//! provider process. It connects to that socket, speaks the same JSON-RPC
//! messages the stdio path already uses, and never stops a daemon it did not
//! start.
//!
//! The control socket speaks RFC 6455 frames, not the newline JSON of the stdio
//! transport, so this module is a carrier only: message framing and decoding
//! stay in `wire`, and no second codec exists here.
use super::wire::{self, Message, RequestId};
use crate::CallContext;
use se_types::{Result, SeError};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn invalid(expected: &str) -> SeError {
    SeError::invalid("Codex daemon connection", expected)
}

/// One retained connection to a login's daemon.
///
/// The socket path is protected state; a failed connect is a named refusal
/// rather than a silent fallback to one process per agent.
pub struct Daemon {
    socket: PathBuf,
    websocket: tokio_tungstenite::WebSocketStream<Stream>,
    lines: wire::Lines,
    requests: wire::Requests,
    pending: Vec<Message>,
}

impl Daemon {
    /// Connect and complete the provider's own greeting.
    ///
    /// `initialize` is a request and `initialized` its notification; the daemon
    /// closes the socket if a client skips either, so both happen before any
    /// thread call is allowed.
    pub async fn connect(socket: &Path, cx: CallContext) -> Result<Self> {
        if !socket.is_absolute() {
            return Err(invalid("an absolute control socket path"));
        }
        let stream = connect(socket, &cx).await?;
        let websocket = tokio_tungstenite::client_async("ws://localhost/", stream)
            .await
            .map_err(|error| invalid(&format!("WebSocket handshake refused: {error}")))?
            .0;
        let mut daemon = Self {
            socket: socket.to_owned(),
            websocket,
            lines: wire::Lines::default(),
            requests: wire::Requests::default(),
            pending: Vec::new(),
        };
        daemon.greet(&cx).await?;
        Ok(daemon)
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// One request whose answer this caller needs.
    ///
    /// Notifications that arrive first are retained in `pending` rather than
    /// dropped, so a turn notification observed while waiting for a response is
    /// still delivered to the loop that consumes it.
    pub async fn request(
        &mut self,
        method: &str,
        params: Value,
        cx: &CallContext,
    ) -> Result<Value> {
        let (id, bytes) = self.requests.request(method, params)?;
        self.send(bytes).await?;
        loop {
            if let Some(message) = self.take_answer(&id)? {
                return match message {
                    Message::Response { result, .. } => result.map_err(|failure| {
                        SeError::invalid(
                            "Codex daemon response",
                            &format!("{} (code {})", failure.message, failure.code),
                        )
                    }),
                    _ => Err(invalid("an answer that was a response")),
                };
            }
            if !self.next_frame(cx).await? {
                return Err(invalid("the daemon closed before answering"));
            }
        }
    }

    /// Send one notification, used for the greeting and for thread control.
    pub async fn notify(&mut self, method: &str, params: Value, cx: &CallContext) -> Result<()> {
        let bytes = wire::notification(method, params)?;
        let _ = cx;
        self.send(bytes).await
    }

    /// The next message this caller has not consumed yet.
    pub async fn next(&mut self, cx: &CallContext) -> Result<Option<Message>> {
        if !self.pending.is_empty() {
            return Ok(Some(self.pending.remove(0)));
        }
        while self.next_frame(cx).await? {
            if let Some(message) = self.pending.pop() {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

    /// Answer the greeting's response, which `request` cannot be used for
    /// because the daemon expects the notification immediately after it.
    async fn greet(&mut self, cx: &CallContext) -> Result<()> {
        let params = serde_json::json!({
            "clientInfo": { "name": "stateengine", "version": env!("CARGO_PKG_VERSION") },
            "capabilities": {},
        });
        let (id, bytes) = self.requests.request("initialize", params)?;
        self.send(bytes).await?;
        loop {
            if self.take_answer(&id)?.is_some() {
                break;
            }
            if !self.next_frame(cx).await? {
                return Err(invalid("the daemon closed during its greeting"));
            }
        }
        self.notify("initialized", Value::Null, cx).await
    }

    fn take_answer(&mut self, id: &RequestId) -> Result<Option<Message>> {
        let position = self.pending.iter().position(
            |message| matches!(message, Message::Response { id: answered, .. } if answered == id),
        );
        Ok(position.map(|at| self.pending.remove(at)))
    }

    async fn send(&mut self, bytes: Vec<u8>) -> Result<()> {
        use futures_util::SinkExt;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("a UTF-8 JSON line"))?
            .trim_end_matches('\n')
            .to_owned();
        self.websocket
            .send(tokio_tungstenite::tungstenite::Message::Text(text.into()))
            .await
            .map_err(|error| invalid(&format!("send refused: {error}")))
    }

    /// Read one text frame into complete messages. Returns false at close.
    async fn next_frame(&mut self, cx: &CallContext) -> Result<bool> {
        use futures_util::StreamExt;
        loop {
            let frame = tokio::time::timeout(cx.timeout, self.websocket.next())
                .await
                .map_err(|_| invalid("the daemon did not answer within its deadline"))?;
            let chunk = match frame {
                None => return Ok(false),
                Some(Err(error)) => return Err(invalid(&format!("receive refused: {error}"))),
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                    text.as_bytes().to_vec()
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(bytes))) => bytes.to_vec(),
                Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => return Ok(false),
                Some(Ok(_)) => continue,
            };
            // A WebSocket text frame carries one complete JSON message and no
            // trailing newline, while the shared decoder frames on newlines.
            // Supply the delimiter here rather than teaching the codec a second
            // framing rule: the bytes are already a complete message.
            let mut framed = chunk;
            framed.push(b'\n');
            let mut offset: usize = 0;
            while offset < framed.len() {
                let (consumed, message) = self.lines.feed(&framed[offset..])?;
                offset = offset.saturating_add(consumed.max(1));
                if let Some(message) = message {
                    self.pending.push(message);
                }
            }
            if !self.pending.is_empty() {
                return Ok(true);
            }
        }
    }
}

#[cfg(unix)]
type Stream = tokio::net::UnixStream;

#[cfg(unix)]
async fn connect(path: &Path, cx: &CallContext) -> Result<Stream> {
    tokio::time::timeout(cx.timeout, tokio::net::UnixStream::connect(path))
        .await
        .map_err(|_| invalid("the control socket did not accept a connection in time"))?
        .map_err(|error| invalid(&format!("connect refused: {error}")))
}

#[cfg(windows)]
type Stream = tokio_util::compat::Compat<async_io::Async<uds_windows::UnixStream>>;

/// Windows has no unix-domain socket in `tokio`; the provider's own client uses
/// `uds_windows` (AF_UNIX on Windows 10+) registered with `async-io`, and this
/// matches it rather than inventing a transport the daemon does not speak.
#[cfg(windows)]
async fn connect(path: &Path, cx: &CallContext) -> Result<Stream> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let path = path.to_owned();
    let connected = tokio::time::timeout(
        cx.timeout,
        tokio::task::spawn_blocking(move || uds_windows::UnixStream::connect(path)),
    )
    .await
    .map_err(|_| invalid("the control socket did not accept a connection in time"))?
    .map_err(|error| invalid(&format!("connect worker failed: {error}")))?
    .map_err(|error| invalid(&format!("connect refused: {error}")))?;
    async_io::Async::new(connected)
        .map(FuturesAsyncReadCompatExt::compat)
        .map_err(|error| invalid(&format!("socket registration failed: {error}")))
}
