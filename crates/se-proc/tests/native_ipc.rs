use se_proc::native_ipc::*;
use std::{
    error::Error,
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn bound(ms: u64) -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_millis(ms),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
#[cfg(unix)]
type Stream = NativeUnixStream;
#[cfg(windows)]
type Stream = NativePipeStream;

struct Endpoint {
    root: PathBuf,
    #[cfg(unix)]
    native: NativeUnixEndpoint,
    #[cfg(windows)]
    native: NativePipeEndpoint,
}
impl Endpoint {
    fn new(label: &str) -> Result<Self> {
        let root = std::env::temp_dir().join(format!("se-ipc-{}-{label}", std::process::id()));
        fs::create_dir(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(unix)]
        let native = NativeUnixEndpoint::bind(&root.join("ipc.sock"))?;
        #[cfg(windows)]
        let native = NativePipeEndpoint::bind(&Self::name(&root))?;
        Ok(Self { root, native })
    }
    #[cfg(windows)]
    fn name(root: &std::path::Path) -> std::ffi::OsString {
        format!(
            r"\\.\pipe\{}",
            root.file_name().unwrap_or_default().to_string_lossy()
        )
        .into()
    }
    fn connect(root: &std::path::Path, limit: IpcIoBound) -> IpcNativeResult<Stream> {
        #[cfg(unix)]
        {
            Stream::connect(&root.join("ipc.sock"), limit)
        }
        #[cfg(windows)]
        {
            Stream::connect(&Self::name(root), limit)
        }
    }
    fn accept(&mut self, limit: IpcIoBound) -> IpcNativeResult<Stream> {
        self.native.accept(limit)
    }
    fn close(self) -> Result<()> {
        #[cfg(unix)]
        self.native.close()?;
        #[cfg(windows)]
        drop(self.native);
        fs::remove_dir(self.root)?;
        Ok(())
    }
}
fn write_binding(stream: &mut Stream, value: &[u8]) -> Result<()> {
    stream.write_all(&(value.len() as u32).to_be_bytes())?;
    stream.write_all(value)?;
    Ok(())
}
fn read_binding(stream: &mut Stream) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    assert!(length < 4096);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[test]
#[ignore = "fixture child driven by real cross-process native IPC test"]
fn ipc_client_child() -> Result<()> {
    let root = PathBuf::from(std::env::var_os("SE_IPC_JUDGE_ROOT").ok_or("fixture root missing")?);
    let mut stream = Endpoint::connect(&root, bound(10_000))?;
    let peer = observe_ipc_peer(stream.channel(), IpcPeerSide::Server)?;
    assert_eq!(
        peer.pid(),
        std::env::var("SE_IPC_JUDGE_PARENT")?.parse::<u32>()?
    );
    write_binding(&mut stream, &observe_ipc_self()?.binding())?;
    assert_eq!(read_binding(&mut stream)?, peer.binding());
    Ok(())
}

#[test]
fn actual_cross_process_credentials_and_image_binding_round_trip() -> Result<()> {
    let mut endpoint = Endpoint::new("peer")?;
    let child = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "ipc_client_child", "--nocapture"])
        .env("SE_IPC_JUDGE_ROOT", &endpoint.root)
        .env("SE_IPC_JUDGE_PARENT", std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stream = endpoint.accept(bound(10_000))?;
    let peer = observe_ipc_peer(stream.channel(), IpcPeerSide::Client)?;
    assert_eq!(peer.pid(), child.id());
    assert_eq!(read_binding(&mut stream)?, peer.binding());
    write_binding(&mut stream, &observe_ipc_self()?.binding())?;
    drop(stream);
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    endpoint.close()
}

#[test]
fn blocked_accept_and_read_keep_their_deadline_and_cancel_bounds() -> Result<()> {
    let mut endpoint = Endpoint::new("bounds")?;
    let begin = Instant::now();
    assert_eq!(
        endpoint
            .accept(bound(30))
            .err()
            .ok_or("accept unexpectedly succeeded")?
            .code,
        IpcNativeErrorCode::TimedOut
    );
    assert!(begin.elapsed() < Duration::from_secs(2));
    let cancelled = bound(10_000);
    cancelled.cancelled.store(true, Ordering::Release);
    assert_eq!(
        endpoint
            .accept(cancelled)
            .err()
            .ok_or("cancelled accept succeeded")?
            .code,
        IpcNativeErrorCode::Cancelled
    );
    let root = endpoint.root.clone();
    let (release, wait) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stream = Endpoint::connect(&root, bound(10_000)).map_err(std::io::Error::other)?;
        wait.recv_timeout(Duration::from_secs(5))
            .map_err(std::io::Error::other)?;
        stream.write_all(b"after")
    });
    let mut stream = endpoint.accept(bound(10_000))?;
    stream.set_bound(bound(30));
    let mut data = [0; 5];
    assert_eq!(
        stream
            .read(&mut data)
            .err()
            .ok_or("idle read succeeded")?
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    let cancelled = bound(10_000);
    cancelled.cancelled.store(true, Ordering::Release);
    stream.set_bound(cancelled);
    assert_eq!(
        stream
            .read(&mut data)
            .err()
            .ok_or("cancelled read succeeded")?
            .kind(),
        std::io::ErrorKind::Interrupted
    );
    stream.set_bound(bound(5_000));
    release.send(())?;
    stream.read_exact(&mut data)?;
    assert_eq!(&data, b"after");
    client.join().map_err(|_| "fixture thread panicked")??;
    drop(stream);
    endpoint.close()
}

#[test]
fn occupied_endpoint_is_never_adopted_or_unlinked() -> Result<()> {
    let endpoint = Endpoint::new("collision")?;
    #[cfg(unix)]
    assert!(NativeUnixEndpoint::bind(&endpoint.root.join("ipc.sock")).is_err());
    #[cfg(windows)]
    assert!(NativePipeEndpoint::bind(&Endpoint::name(&endpoint.root)).is_err());
    endpoint.close()
}

#[cfg(unix)]
#[test]
fn unsafe_paths_and_replaced_socket_refuse_without_removing_foreign_data() -> Result<()> {
    use std::os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    };
    let endpoint = Endpoint::new("paths")?;
    let root = endpoint.root.clone();
    let path = root.join("ipc.sock");
    fs::remove_file(&path)?;
    fs::write(&path, b"foreign replacement")?;
    assert!(endpoint.native.close().is_err());
    assert_eq!(fs::read(&path)?, b"foreign replacement");
    assert!(NativeUnixEndpoint::bind(&path).is_err());
    assert_eq!(fs::read(&path)?, b"foreign replacement");
    assert!(NativeUnixStream::connect(&path, bound(100)).is_err());
    fs::remove_file(&path)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    assert!(NativeUnixEndpoint::bind(&path).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let linked = root.with_extension("linked");
    symlink(&root, &linked)?;
    assert!(NativeUnixEndpoint::bind(&linked.join("ipc.sock")).is_err());
    fs::remove_file(linked)?;
    let foreign = UnixListener::bind(&path)?;
    assert!(NativeUnixEndpoint::bind(&path).is_err());
    drop(foreign);
    fs::remove_file(path)?;
    fs::remove_dir(root)?;
    Ok(())
}
