//! Native client reads must drain bytes after server close within the original bound.
#![cfg(unix)]
use se_proc::native_ipc::{IpcIoBound, NativeUnixStream};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Connection {
    root: PathBuf,
    client: NativeUnixStream,
    server: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl Connection {
    fn new(milliseconds: u64) -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "se-buffered-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let socket = root.join("ipc.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let client = NativeUnixStream::connect(
            &socket,
            IpcIoBound {
                deadline: Instant::now() + Duration::from_millis(milliseconds),
                cancelled: cancelled.clone(),
            },
        )?;
        let (server, _) = listener.accept()?;
        Ok(Self {
            root,
            client,
            server,
            cancelled,
        })
    }
    fn close(self) -> Result {
        drop(self.client);
        drop(self.server);
        fs::remove_file(self.root.join("ipc.sock"))?;
        fs::remove_dir(self.root)?;
        Ok(())
    }
}

#[test]
fn buffered_native_reply_survives_peer_shutdown_then_reports_eof() -> Result {
    let mut connection = Connection::new(5_000)?;
    let expected = b"buffered-native-reply";
    connection.server.write_all(expected)?;
    connection.server.shutdown(std::net::Shutdown::Both)?;
    // Force the late read to begin only after the sender has closed its direction.
    let mut actual = vec![0; expected.len()];
    connection.client.read_exact(&mut actual)?;
    assert_eq!(actual, expected);
    assert_eq!(connection.client.read(&mut [0; 1])?, 0);
    connection.close()
}

#[test]
fn quiet_native_peer_keeps_the_original_read_deadline() -> Result {
    let mut connection = Connection::new(250)?;
    let started = Instant::now();
    let error = connection
        .client
        .read(&mut [0; 1])
        .expect_err("quiet peer unexpectedly supplied bytes");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "read lost its original deadline"
    );
    connection.close()
}

#[test]
fn cancelled_native_read_does_not_wait_for_peer_activity() -> Result {
    let mut connection = Connection::new(5_000)?;
    connection.cancelled.store(true, Ordering::Release);
    let started = Instant::now();
    let error = connection
        .client
        .read(&mut [0; 1])
        .expect_err("cancelled read unexpectedly succeeded");
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(started.elapsed() < Duration::from_secs(1));
    connection.close()
}

#[test]
fn closed_peer_write_returns_an_error_without_terminating_the_client() -> Result {
    let mut connection = Connection::new(5_000)?;
    connection.server.shutdown(std::net::Shutdown::Both)?;
    let error = connection
        .client
        .write_all(b"closed-peer-write")
        .expect_err("write to closed peer succeeded");
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NotConnected
        ),
        "closed peer returned an unexpected error: {error}"
    );
    connection.close()
}

#[test]
fn blocked_native_write_keeps_the_original_deadline() -> Result {
    let mut connection = Connection::new(250)?;
    let started = Instant::now();
    // The accepted peer stays alive without draining its receive buffer.
    let error = connection
        .client
        .write_all(&vec![0; 4 * 1024 * 1024])
        .expect_err("quiet peer accepted an unbounded write");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "write lost its original deadline"
    );
    connection.close()
}
