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
//! because that means the server is gone. The socket is AF_UNIX on Windows too.
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};

pub const ENTRY: &str = "--stateengine-private-codex-forward";

#[cfg(unix)]
type Upstream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Upstream = uds_windows::UnixStream;
#[cfg(unix)]
type Listener = std::os::unix::net::UnixListener;
#[cfg(windows)]
type Listener = uds_windows::UnixListener;

/// `se ENTRY <private socket> <control socket>`. Returns when the agent's
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
    pipe_socket(Path::new(downstream), control)
}

/// Serve the private socket until the server closes a connection first.
fn pipe_socket(path: &Path, control: PathBuf) -> io::Result<()> {
    use std::net::Shutdown;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let listener = Listener::bind(path)?;
    // The host accepts only an owner-only endpoint; the directory is private too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    // What this forwarder bound, so its exit removes only that endpoint.
    let bound = crate::identity::ObjectId::local_socket(path)?;
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
                        let server = match Upstream::connect(&control) {
                            Ok(server) => server,
                            // Only an absent or refusing socket means the server is gone;
                            // any other failure ends this one connection.
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                                ) || (cfg!(windows) && e.raw_os_error() == Some(10050)) =>
                            {
                                let _ = ended.send(io::Error::other(
                                    "the login's app-server no longer accepts connections",
                                ));
                                return;
                            }
                            Err(_) => return,
                        };
                        let (Ok(mut client_in), Ok(mut server_out)) =
                            (client.try_clone(), server.try_clone())
                        else {
                            return;
                        };
                        // Host to server on its own thread; server to host here. The
                        // flag is set before the shutdown that ends the copy below,
                        // so a client that left first is never read as a lost server.
                        let client_left = Arc::new(AtomicBool::new(false));
                        let left = Arc::clone(&client_left);
                        let to_server = std::thread::spawn(move || {
                            let _ = io::copy(&mut client_in, &mut server_out);
                            left.store(true, Ordering::Release);
                            let _ = server_out.shutdown(Shutdown::Both);
                        });
                        let (mut server_in, mut client_out) = (server, client);
                        let copied = io::copy(&mut server_in, &mut client_out);
                        let client_finished = client_left.load(Ordering::Acquire);
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
    // Remove only the endpoint this forwarder bound; anything else is kept.
    if let Err(error) = bound.remove_local_socket(path) {
        eprintln!(
            "codex forwarder: {} was not removed: {error}",
            path.display()
        );
    }
    Err(reason)
}
