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

/// The shared daemon ended while this agent was using it.
///
/// This is a named stopped state, not a usage mistake: the login's one process
/// is gone, so every agent that was attached to it has nothing to talk to. The
/// step names what a person can do now; (b) adds automatic reattach later, and
/// nothing here pretends this call can continue on a replacement server.
fn ended(detail: &str) -> SeError {
    SeError::new(se_types::Detail::ProviderIncompatible(
        se_types::details::ProviderIncompatible {
            subject: "Codex shared daemon".into(),
            reason: format!("the login's app-server stopped while this agent was attached ({detail})"),
            next_step: "Relaunch the agent; its conversation is retained and is not automatically reattached to a new server".into(),
        },
    ))
}

/// Where one login's daemon keeps its control socket.
///
/// The provider derives this path from `CODEX_HOME`; StateEngine derives the same
/// path from the same home so both name one socket, and it never guesses across
/// logins. A caller that names no home has no login to serve and is refused.
pub fn control_socket(codex_home: &Path) -> PathBuf {
    codex_home
        .join("app-server-control")
        .join("app-server-control.sock")
}

/// Whether a control socket is already served.
///
/// The answer decides ownership, not convenience: a live socket means someone
/// started this login's daemon, and a process we did not start is never attached
/// to. `NotFound` and `ConnectionRefused` are absent, because a stale socket file
/// is not a running daemon; every other error is a refusal that keeps its reason.
pub async fn socket_is_served(socket: &Path, cx: &CallContext) -> Result<bool> {
    match tokio::time::timeout(cx.timeout, probe(socket)).await {
        Ok(Ok(true)) => Ok(true),
        Ok(Ok(false)) => Ok(false),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(invalid("a control socket answer within the deadline")),
    }
}

/// Whether a socket at `socket` accepts a connection, keeping the operating
/// system's own distinction between absent and refused.
///
/// A missing path and a refused connection are both "not served": a stale file
/// left by a dead daemon is exactly the refused case. A third error (permission,
/// too many files) is returned as itself rather than read as absence.
async fn probe(socket: &Path) -> Result<bool> {
    if !socket.is_absolute() {
        return Err(invalid("an absolute control socket path"));
    }
    match raw_open(socket).await {
        Ok(stream) => {
            drop(stream);
            Ok(true)
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(se_core::scope::unreadable(
            "Codex control socket",
            &error.to_string(),
        )),
    }
}

/// Refuse to use a login whose daemon is already served by someone else.
///
/// StateEngine owns the daemons it starts so that it can account for their
/// lifetime, and a user's own desktop daemon is not ours to stop or replace.
pub async fn require_unserved(socket: &Path, cx: &CallContext) -> Result<()> {
    if socket_is_served(socket, cx).await? {
        return Err(SeError::new(se_types::Detail::ProviderIncompatible(
            se_types::details::ProviderIncompatible {
                subject: "Codex shared daemon".into(),
                reason: format!(
                    "this login already has a daemon that StateEngine did not start ({})",
                    socket.display()
                ),
                next_step: "Close that daemon and relaunch the agent, or launch it with a different CODEX_HOME".into(),
            },
        )));
    }
    Ok(())
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
        // One deadline governs the whole call. A shared daemon serves several
        // agents, so a busy neighbour can keep notifications arriving; a refusal
        // that re-armed its clock on every frame would never expire.
        let end = tokio::time::Instant::now() + cx.timeout;
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
            let left = end.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(invalid("an answer within the original deadline"));
            }
            if !self
                .next_frame(&CallContext {
                    generation: cx.generation,
                    timeout: left,
                    cancellation: std::sync::Arc::clone(&cx.cancellation),
                })
                .await?
            {
                return Err(ended("it closed before answering"));
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
                return Err(ended("it closed during its greeting"));
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
async fn raw_open(path: &Path) -> std::io::Result<Stream> {
    tokio::net::UnixStream::connect(path).await
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
mod windows {
    //! The provider's own client registers a Windows AF_UNIX socket with
    //! `async-io`, which needs `AsSocket` and an `IoSafe` assertion that the
    //! provider's crate does not implement. This is the same thin owner of the
    //! same handle: no buffering of its own, so moving it between tasks is sound.
    use std::io;
    use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket};
    use std::path::Path;

    struct Registered(uds_windows::UnixStream);

    impl From<uds_windows::UnixStream> for Registered {
        fn from(stream: uds_windows::UnixStream) -> Self {
            Self(stream)
        }
    }

    impl AsSocket for Registered {
        fn as_socket(&self) -> BorrowedSocket<'_> {
            // The wrapped stream outlives this borrow; it owns the handle.
            unsafe { BorrowedSocket::borrow_raw(self.0.as_raw_socket()) }
        }
    }

    impl io::Read for Registered {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            io::Read::read(&mut self.0, buffer)
        }
    }

    impl io::Write for Registered {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            io::Write::write(&mut self.0, buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            io::Write::flush(&mut self.0)
        }
    }

    // Every read and write is passed straight through to the socket, so the
    // registration cannot outlive or observe a reordered buffer.
    unsafe impl async_io::IoSafe for Registered {}

    pub(super) type Stream = tokio_util::compat::Compat<async_io::Async<Registered>>;

    pub(super) async fn connect(path: &Path) -> io::Result<Stream> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let path = path.to_owned();
        let stream = tokio::task::spawn_blocking(move || uds_windows::UnixStream::connect(path))
            .await
            .map_err(io::Error::other)??;
        async_io::Async::new(Registered::from(stream)).map(FuturesAsyncReadCompatExt::compat)
    }
}

#[cfg(windows)]
async fn raw_open(path: &Path) -> std::io::Result<Stream> {
    windows::connect(path).await
}

#[cfg(windows)]
type Stream = windows::Stream;

/// Windows has no unix-domain socket in `tokio`; the provider's own client uses
/// `uds_windows` (AF_UNIX on Windows 10+) registered with `async-io`, and this
/// matches it rather than inventing a transport the daemon does not speak.
#[cfg(windows)]
async fn connect(path: &Path, cx: &CallContext) -> Result<Stream> {
    tokio::time::timeout(cx.timeout, windows::connect(path))
        .await
        .map_err(|_| invalid("the control socket did not accept a connection in time"))?
        .map_err(|error| invalid(&format!("connect refused: {error}")))
}
