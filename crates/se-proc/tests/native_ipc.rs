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
    if std::env::var_os("SE_IPC_JUDGE_OVERSIZED").is_some() {
        assert_eq!(stream.read(&mut [0])?, 0, "oversized peer was admitted");
        return Ok(());
    }
    let peer = observe_ipc_peer(stream.channel(), IpcPeerSide::Server)?;
    write_binding(&mut stream, &observe_ipc_self()?.binding())?;
    assert_eq!(read_binding(&mut stream)?, peer.binding());
    assert_eq!(
        peer.pid(),
        std::env::var("SE_IPC_JUDGE_PARENT")?.parse::<u32>()?
    );
    Ok(())
}

#[test]
fn native_executable_proof_obeys_its_original_bound() -> Result<()> {
    let cancelled = bound(10_000);
    cancelled.cancelled.store(true, Ordering::Release);
    assert_eq!(
        observe_ipc_self_bounded(&cancelled)
            .err()
            .ok_or("cancelled proof succeeded")?
            .code,
        IpcNativeErrorCode::Cancelled
    );
    let begin = Instant::now();
    assert_eq!(
        observe_ipc_self_bounded(&bound(1))
            .err()
            .ok_or("one-millisecond proof unexpectedly finished")?
            .code,
        IpcNativeErrorCode::TimedOut
    );
    assert!(
        begin.elapsed() < Duration::from_secs(2),
        "hashing continued after the absolute proof deadline"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn trusted_ancestor_link_and_private_final_directory_can_host_an_endpoint() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let outer = Endpoint::new("ancestor")?;
    let root = outer.root.clone();
    let private = root.join("private");
    fs::create_dir(&private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
    let alias = root.with_extension("alias");
    symlink(&root, &alias)?;
    let endpoint = NativeUnixEndpoint::bind(&alias.join("private/ipc.sock"))?;
    endpoint.close()?;
    fs::remove_file(alias)?;
    fs::remove_dir(private)?;
    outer.close()
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_real_peer_image_is_refused_before_unbounded_content_read() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut endpoint = Endpoint::new("oversized")?;
    let image = endpoint.root.join("oversized-image");
    fs::copy(std::env::current_exe()?, &image)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&image)?
        .set_len(512 * 1024 * 1024 + 1)?;
    fs::set_permissions(&image, fs::Permissions::from_mode(0o700))?;
    let child = Command::new(&image)
        .args(["--ignored", "--exact", "ipc_client_child", "--nocapture"])
        .env("SE_IPC_JUDGE_ROOT", &endpoint.root)
        .env("SE_IPC_JUDGE_OVERSIZED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let refusal = endpoint
        .accept(bound(5_000))
        .err()
        .ok_or("oversized native peer was accepted")?;
    assert_eq!(refusal.code, IpcNativeErrorCode::Unreadable);
    assert!(refusal.operation.contains("512 MiB"));
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_file(image)?;
    endpoint.close()
}

#[cfg(windows)]
#[test]
fn protected_reservation_holds_the_name_until_its_native_handles_close() -> Result<()> {
    let root = std::env::temp_dir().join(format!("se-ipc-{}-reservation", std::process::id()));
    let name = Endpoint::name(&root);
    let reservation = NativePipeReservation::create(&name)?;
    assert!(NativePipeEndpoint::bind(&name).is_err());
    assert_eq!(
        NativePipeStream::connect(&name, bound(30))
            .err()
            .ok_or("occupied reservation accepted a call")?
            .code,
        IpcNativeErrorCode::TimedOut
    );
    drop(reservation);
    drop(NativePipeEndpoint::bind(&name)?);
    Ok(())
}

#[cfg(windows)]
#[test]
fn client_refuses_a_real_pipe_with_a_world_access_dacl() -> Result<()> {
    use std::{
        mem::size_of,
        os::windows::{
            ffi::OsStrExt,
            io::{FromRawHandle, OwnedHandle},
        },
    };
    use windows_sys::Win32::{
        Foundation::*,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
        },
        System::Pipes::*,
    };
    let IpcPrincipal::Windows { sid } = observe_ipc_self()?.principal().clone() else {
        return Err("Windows SID missing".into());
    };
    let descriptor: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;WD)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut security = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            1,
            &mut security,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let root = std::env::temp_dir().join(format!("se-ipc-{}-world-dacl", std::process::id()));
    let name = Endpoint::name(&root);
    let wide: Vec<_> = name.encode_wide().chain(Some(0)).collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            &attributes,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        LocalFree(security);
    }
    if raw == INVALID_HANDLE_VALUE {
        return Err(error.into());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    assert_eq!(
        NativePipeStream::connect(&name, bound(1_000))
            .err()
            .ok_or("world-access pipe was accepted")?
            .code,
        IpcNativeErrorCode::UnsafeEndpoint
    );
    drop(handle);
    drop(NativePipeEndpoint::bind(&name)?);
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
