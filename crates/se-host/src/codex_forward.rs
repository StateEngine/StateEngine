//! One agent's forwarder to its login's shared Codex app-server.
//!
//! The agent's native process is this forwarder, not a Codex process, so the
//! login keeps one app-server and one token owner however many agents run.
//!
//! On a private socket it is a byte pipe: every connection the host (or an
//! attended terminal) opens gets its own fresh connection to the login's control
//! socket, and the client's own protocol runs end to end. The stock server keeps
//! a running turn when a client connection closes, so a host that dies or
//! restarts loses only its connection; the next host connects again and resumes
//! the thread. The forwarder ends only when the server ends a connection first,
//! because that means the server is gone.
//!
//! Where the host can only offer stdio (Windows), the forwarder bridges the
//! host's newline-delimited JSON to the server's WebSocket text frames, without
//! reading the messages. Stdio cannot be reopened, so its end is the agent's.
use std::{
    ffi::OsString,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
};

pub const ENTRY: &str = "--stateengine-private-codex-forward";
/// Downstream given as this value is the forwarder's own stdio.
pub const STDIO: &str = "-";
/// The stock server's advertised largest unfragmented message.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[cfg(unix)]
type Upstream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Upstream = uds_windows::UnixStream;

/// `se ENTRY <private socket | -> <control socket>`. Returns when the agent's
/// provider has ended.
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
    // Refuse at once, rather than at the first host connection, when the
    // login's server is not there to forward to.
    drop(Upstream::connect(&control)?);
    if downstream == STDIO {
        return bridge_stdio(&control);
    }
    #[cfg(unix)]
    {
        pipe_socket(Path::new(downstream), control)
    }
    #[cfg(windows)]
    {
        Err(io::Error::other("this platform offers the host only stdio"))
    }
}

/// Serve the private socket until the server closes a connection first.
#[cfg(unix)]
fn pipe_socket(path: &Path, control: PathBuf) -> io::Result<()> {
    use std::net::Shutdown;
    use std::os::unix::net::UnixListener;
    let listener = UnixListener::bind(path)?;
    // The host accepts only an owner-only endpoint; the directory is private too.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let (ended, server_gone) = std::sync::mpsc::channel::<io::Error>();
    std::thread::Builder::new()
        .name("se-codex-forward-accept".into())
        .spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { continue };
                let control = control.clone();
                let ended = ended.clone();
                let _ = std::thread::Builder::new()
                    .name("se-codex-forward-connection".into())
                    .spawn(move || {
                        let Ok(server) = Upstream::connect(&control) else {
                            let _ = ended.send(io::Error::other(
                                "the login's app-server no longer accepts connections",
                            ));
                            return;
                        };
                        let (Ok(mut client_in), Ok(mut server_out)) =
                            (client.try_clone(), server.try_clone())
                        else {
                            return;
                        };
                        // Host to server on its own thread; server to host here.
                        let to_server = std::thread::spawn(move || {
                            let _ = io::copy(&mut client_in, &mut server_out);
                            // The client finished first: end this connection only.
                            let _ = server_out.shutdown(Shutdown::Both);
                        });
                        let (mut server_in, mut client_out) = (server, client);
                        let copied = io::copy(&mut server_in, &mut client_out);
                        let client_finished = to_server.is_finished();
                        let _ = client_out.shutdown(Shutdown::Both);
                        let _ = to_server.join();
                        if !client_finished {
                            // The server closed while its client was still there.
                            let _ = ended.send(copied.err().unwrap_or_else(|| {
                                io::Error::other("the login's app-server closed a connection")
                            }));
                        }
                    });
            }
        })?;
    let reason = server_gone
        .recv()
        .unwrap_or_else(|_| io::Error::other("the private socket stopped accepting"));
    let _ = std::fs::remove_file(path);
    Err(reason)
}

/// Bridge stdio lines to WebSocket text frames for the life of the agent.
fn bridge_stdio(control: &Path) -> io::Result<()> {
    let (mut reader, writer) = connect(control)?;
    let writer = std::sync::Arc::new(std::sync::Mutex::new(writer));
    let pong = std::sync::Arc::clone(&writer);
    std::thread::Builder::new()
        .name("se-codex-forward-input".into())
        .spawn(move || {
            let mut input = io::stdin().lock();
            let mut line = Vec::new();
            loop {
                line.clear();
                let read = (&mut input)
                    .take(MAX_MESSAGE as u64 + 1)
                    .read_until(b'\n', &mut line);
                // The host's end is the agent's end; a partial last line is
                // never sent as a message.
                if !matches!(read, Ok(n) if n > 0) || line.last() != Some(&b'\n') {
                    std::process::exit(0);
                }
                line.pop();
                let sent = writer
                    .lock()
                    .map_err(|_| io::Error::other("poisoned"))
                    .and_then(|mut upstream| write_frame(&mut *upstream, 0x1, &line));
                if sent.is_err() {
                    std::process::exit(1);
                }
            }
        })?;
    let mut output = io::stdout().lock();
    let mut message = Vec::new();
    loop {
        let Some((fin, opcode, payload)) = read_frame(&mut reader)? else {
            return Err(io::Error::other(
                "the login's app-server closed the connection",
            ));
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
                    message.push(b'\n');
                    output.write_all(&message)?;
                    output.flush()?;
                    message.clear();
                }
            }
            0x8 => {
                return Err(io::Error::other(
                    "the login's app-server closed the connection",
                ));
            }
            0x9 => {
                let mut upstream = pong.lock().map_err(|_| io::Error::other("poisoned"))?;
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
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        base64(&key)
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
    Ok(Some((head[0] & 0x80 != 0, head[0] & 0x0F, payload)))
}

/// Client frames are masked, as the protocol requires.
fn write_frame(stream: &mut impl Write, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut mask = [0_u8; 4];
    se_proc::fill_entropy(&mut mask).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    let length = payload.len();
    if let Ok(small @ 0..=125) = u8::try_from(length) {
        frame.push(0x80 | small);
    } else if let Ok(medium) = u16::try_from(length) {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&medium.to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(length as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
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
            out.push(if i <= chunk.len() {
                char::from(TABLE[(n >> (18 - 6 * i) & 63) as usize])
            } else {
                '='
            });
        }
    }
    out
}
