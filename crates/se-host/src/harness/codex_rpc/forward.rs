//! One agent's forwarder to its login's shared Codex app-server.
//!
//! The agent's native process is this forwarder, not a Codex process. It holds
//! one upstream connection to the login's control socket for its whole life and
//! offers the host the same newline-delimited JSON transport a private Codex
//! app-server used to, on the same private socket. A host that dies or restarts
//! therefore only drops its downstream connection: the upstream connection, and
//! any turn running on it, continue, and the next host reconnects to the same
//! socket and resumes the thread.
//!
//! The forwarder carries whole messages and never reads them. It translates
//! WebSocket text frames to lines and back so that every downstream connection
//! starts on a message boundary. While no host is connected it keeps a bounded
//! backlog and drops the oldest messages past it; a reconnecting host rereads
//! the thread rather than trusting what it missed.
use std::{
    collections::VecDeque,
    ffi::OsString,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const ENTRY: &str = "--stateengine-private-codex-forward";
/// The stock server's advertised largest unfragmented message.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Server messages kept while no host is connected.
const BACKLOG_BYTES: usize = 8 * 1024 * 1024;
/// Downstream given as this value is the forwarder's own stdio.
pub const STDIO: &str = "-";

#[cfg(unix)]
type Upstream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Upstream = uds_windows::UnixStream;

/// `se ENTRY <downstream socket or -> <control socket>`. Returns when the
/// upstream connection ends; that is the agent's provider ending.
pub fn private_entry(args: &[OsString]) -> io::Result<()> {
    let [_, _, downstream, control] = args else {
        return Err(io::Error::other(
            "the forwarder takes a downstream socket and a control socket",
        ));
    };
    let control = PathBuf::from(control);
    if !control.is_absolute() {
        return Err(io::Error::other("the control socket path must be absolute"));
    }
    let (reader, writer) = connect(&control)?;
    let writer = Arc::new(Mutex::new(writer));
    let hosts = Arc::new(Mutex::new(Hosts::default()));
    {
        let hosts = Arc::clone(&hosts);
        let writer = Arc::clone(&writer);
        let downstream = downstream.clone();
        std::thread::Builder::new()
            .name("se-codex-forward-host".into())
            .spawn(move || accept(&downstream, &hosts, &writer))?;
    }
    let ended = pump_upstream(reader, &writer, &hosts);
    if let Ok(mut hosts) = hosts.lock() {
        hosts.current = None;
    }
    ended
}

/// The connected host, if any, and what arrived while none was.
#[derive(Default)]
struct Hosts {
    current: Option<(u64, Box<dyn Write + Send>)>,
    connections: u64,
    backlog: VecDeque<Vec<u8>>,
    backlog_bytes: usize,
    dropped: u64,
}

impl Hosts {
    /// Deliver one complete line. A host that can no longer be written is
    /// detached and the line waits for the next host, which starts at it.
    fn deliver(&mut self, line: Vec<u8>) {
        if let Some((_, host)) = self.current.as_mut() {
            if host.write_all(&line).and_then(|()| host.flush()).is_ok() {
                return;
            }
            self.current = None;
        }
        self.backlog_bytes = self.backlog_bytes.saturating_add(line.len());
        self.backlog.push_back(line);
        while self.backlog_bytes > BACKLOG_BYTES {
            let Some(oldest) = self.backlog.pop_front() else {
                break;
            };
            self.backlog_bytes = self.backlog_bytes.saturating_sub(oldest.len());
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// Forget a host whose input ended, unless a newer one replaced it.
    fn detach(&mut self, connection: u64) {
        if self.current.as_ref().is_some_and(|(id, _)| *id == connection) {
            self.current = None;
        }
    }

    /// Install a new host and hand it the backlog in order.
    fn attach(&mut self, mut host: Box<dyn Write + Send>) -> u64 {
        self.connections = self.connections.wrapping_add(1);
        let connection = self.connections;
        if self.dropped > 0 {
            eprintln!(
                "codex forwarder: {} server messages were dropped while no host was connected",
                self.dropped
            );
            self.dropped = 0;
        }
        self.current = None;
        while let Some(line) = self.backlog.front() {
            if host.write_all(line).is_err() {
                return connection;
            }
            self.backlog_bytes = self.backlog_bytes.saturating_sub(line.len());
            self.backlog.pop_front();
        }
        if host.flush().is_ok() {
            self.current = Some((connection, host));
        }
        connection
    }
}

/// Accept hosts one at a time; a new connection replaces the previous one.
fn accept(downstream: &OsString, hosts: &Arc<Mutex<Hosts>>, writer: &Arc<Mutex<Upstream>>) {
    if downstream == STDIO {
        let output: Box<dyn Write + Send> = Box::new(io::stdout());
        if let Ok(mut hosts) = hosts.lock() {
            let _ = hosts.attach(output);
        }
        // Stdio cannot be reopened by another host, so its end is the agent's.
        let _ = pump_host(io::stdin().lock(), writer);
        std::process::exit(0);
    }
    #[cfg(unix)]
    {
        let path = Path::new(downstream);
        let listener = match std::os::unix::net::UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("codex forwarder: cannot listen on {}: {error}", path.display());
                std::process::exit(1);
            }
        };
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(output) = stream.try_clone() else {
                continue;
            };
            let Ok(connection) = hosts.lock().map(|mut hosts| hosts.attach(Box::new(output)))
            else {
                continue;
            };
            let writer = Arc::clone(writer);
            let hosts = Arc::clone(hosts);
            let _ = std::thread::Builder::new()
                .name("se-codex-forward-input".into())
                .spawn(move || {
                    let _ = pump_host(BufReader::new(stream), &writer);
                    if let Ok(mut hosts) = hosts.lock() {
                        hosts.detach(connection);
                    }
                });
        }
    }
    #[cfg(windows)]
    {
        eprintln!("codex forwarder: this platform offers the host only stdio");
        std::process::exit(1);
    }
}

/// Host lines become upstream text frames. A partial line left by a host that
/// went away is discarded, so the server never sees a broken message.
fn pump_host(input: impl BufRead, writer: &Arc<Mutex<Upstream>>) -> io::Result<()> {
    let mut input = input.take(u64::MAX);
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut input)
            .take(MAX_MESSAGE as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 || line.last() != Some(&b'\n') {
            return Ok(());
        }
        line.pop();
        let mut upstream = writer.lock().map_err(|_| io::Error::other("poisoned"))?;
        write_frame(&mut *upstream, 0x1, &line)?;
    }
}

/// Upstream text messages become host lines until the server closes.
fn pump_upstream(
    mut reader: Upstream,
    writer: &Arc<Mutex<Upstream>>,
    hosts: &Arc<Mutex<Hosts>>,
) -> io::Result<()> {
    let mut message = Vec::new();
    loop {
        let Some((fin, opcode, payload)) = read_frame(&mut reader)? else {
            return Ok(());
        };
        match opcode {
            0x1 | 0x0 => {
                if message.len().saturating_add(payload.len()) > MAX_MESSAGE {
                    return Err(io::Error::other("server message exceeds its bound"));
                }
                message.extend_from_slice(&payload);
                if fin {
                    if message.contains(&b'\n') {
                        return Err(io::Error::other(
                            "server message contains a line break and cannot be framed as a line",
                        ));
                    }
                    let mut line = std::mem::take(&mut message);
                    line.push(b'\n');
                    hosts
                        .lock()
                        .map_err(|_| io::Error::other("poisoned"))?
                        .deliver(line);
                }
            }
            0x8 => return Ok(()),
            0x9 => {
                let mut upstream = writer.lock().map_err(|_| io::Error::other("poisoned"))?;
                write_frame(&mut *upstream, 0xA, &payload)?;
            }
            0xA => {}
            _ => return Err(io::Error::other("server sent an unsupported frame")),
        }
    }
}

/// Open the control socket and complete the WebSocket upgrade.
fn connect(control: &Path) -> io::Result<(Upstream, Upstream)> {
    let mut stream = Upstream::connect(control)?;
    let mut key = [0_u8; 16];
    se_proc::fill_entropy(&mut key).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let key = base64(&key);
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )?;
    stream.flush()?;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("control socket upgrade reply is too long"));
        }
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let status = head.split(|&b| b == b'\n').next().unwrap_or_default();
    if !status.starts_with(b"HTTP/1.1 101") {
        return Err(io::Error::other(format!(
            "control socket refused the upgrade: {}",
            String::from_utf8_lossy(status).trim()
        )));
    }
    let reader = stream.try_clone()?;
    Ok((reader, stream))
}

fn read_frame(stream: &mut impl Read) -> io::Result<Option<(bool, u8, Vec<u8>)>> {
    let mut head = [0_u8; 2];
    match stream.read_exact(&mut head) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let fin = head[0] & 0x80 != 0;
    let opcode = head[0] & 0x0F;
    if head[1] & 0x80 != 0 {
        return Err(io::Error::other("server frames must not be masked"));
    }
    let length = match head[1] & 0x7F {
        126 => {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes)?;
            u64::from(u16::from_be_bytes(bytes))
        }
        127 => {
            let mut bytes = [0_u8; 8];
            stream.read_exact(&mut bytes)?;
            u64::from_be_bytes(bytes)
        }
        small => u64::from(small),
    };
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length <= MAX_MESSAGE)
        .ok_or_else(|| io::Error::other("server frame exceeds its bound"))?;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(Some((fin, opcode, payload)))
}

/// Client frames are masked, as the protocol requires.
fn write_frame(stream: &mut impl Write, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut mask = [0_u8; 4];
    se_proc::fill_entropy(&mut mask).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => frame.push(0x80 | n as u8),
        n if n <= usize::from(u16::MAX) => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    stream.write_all(&frame)?;
    stream.flush()
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
