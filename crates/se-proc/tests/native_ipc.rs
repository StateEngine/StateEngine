#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_proc::native_ipc::*;
use std::{
    error::Error,
    fs,
    path::PathBuf,
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
struct Endpoint {
    root: PathBuf,
    #[cfg(unix)]
    native: NativeUnixEndpoint,
    #[cfg(windows)]
    native: NativePipeReservation,
    _root_owner: cleanup_directory::PrivateDirectory,
}
impl Endpoint {
    fn new(label: &str) -> Result<Self> {
        let root = std::env::temp_dir().join(format!("se-ipc-{}-{label}", std::process::id()));
        fs::create_dir(&root)?;
        let root_owner = cleanup_directory::PrivateDirectory::for_case(root.clone());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(unix)]
        let native = NativeUnixEndpoint::bind(&root.join("ipc.sock"))?;
        #[cfg(windows)]
        let native = NativePipeReservation::create(&Self::name(&root))?;
        Ok(Self {
            root,
            native,
            _root_owner: root_owner,
        })
    }
    #[cfg(windows)]
    fn name(root: &std::path::Path) -> std::ffi::OsString {
        format!(
            r"\\.\pipe\{}",
            root.file_name().unwrap_or_default().to_string_lossy()
        )
        .into()
    }
    fn close(self) -> Result<()> {
        #[cfg(unix)]
        self.native.close()?;
        #[cfg(windows)]
        drop(self.native);
        self._root_owner.finish(Ok(()))
    }
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
    let expired = IpcIoBound {
        deadline: begin,
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    assert_eq!(
        observe_ipc_self_bounded(&expired)
            .err()
            .ok_or("expired proof unexpectedly finished")?
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

#[cfg(windows)]
#[test]
fn protected_reservation_holds_the_name_until_its_native_handles_close() -> Result<()> {
    let root = std::env::temp_dir().join(format!("se-ipc-{}-reservation", std::process::id()));
    let name = Endpoint::name(&root);
    let reservation = NativePipeReservation::create(&name)?;
    assert!(NativePipeReservation::create(&name).is_err());
    assert_eq!(
        NativePipeStream::connect(&name, bound(30))
            .err()
            .ok_or("occupied reservation accepted a call")?
            .code,
        IpcNativeErrorCode::TimedOut
    );
    drop(reservation);
    drop(NativePipeReservation::create(&name)?);
    Ok(())
}

#[cfg(windows)]
fn world_access_pipe(
    label: &str,
) -> Result<(
    std::os::windows::io::OwnedHandle,
    std::ffi::OsString,
    String,
)> {
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
    // SAFETY: live NUL-terminated SDDL and writable allocation output.
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
    let root = std::env::temp_dir().join(format!("se-ipc-{}-{label}", std::process::id()));
    let name = Endpoint::name(&root);
    let wide: Vec<_> = name.encode_wide().chain(Some(0)).collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security,
        bInheritHandle: 0,
    };
    // SAFETY: descriptor, attributes and pipe name outlive this native allocation.
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
    // SAFETY: the descriptor was allocated by the preceding conversion call.
    unsafe {
        LocalFree(security);
    }
    if raw == INVALID_HANDLE_VALUE {
        return Err(error.into());
    }
    // SAFETY: successful CreateNamedPipeW transfers one unique handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    Ok((handle, name, sid))
}

#[cfg(windows)]
#[test]
fn squatter_refusal_retains_owner_or_unreadable_cause_and_legal_action() -> Result<()> {
    let (handle, name, sid) = world_access_pipe("squatter")?;
    let collision = NativePipeReservation::create(&name)
        .err()
        .ok_or("squatter pipe adopted")?;
    let reason = collision.to_string();
    assert!(
        reason.contains("SID")
            && reason.contains("owner")
            && reason.contains("unused protected name")
            && (reason.contains(&sid) || reason.contains("unreadable")),
        "squatter refusal lost its owner/cause/action: {reason}"
    );
    drop(handle);
    drop(NativePipeReservation::create(&name)?);
    Ok(())
}

#[cfg(windows)]
#[test]
fn client_refuses_a_real_pipe_with_a_world_access_dacl() -> Result<()> {
    let (handle, name, _) = world_access_pipe("world-dacl")?;
    assert_eq!(
        NativePipeStream::connect(&name, bound(1_000))
            .err()
            .ok_or("world-access pipe was accepted")?
            .code,
        IpcNativeErrorCode::UnsafeEndpoint
    );
    drop(handle);
    drop(NativePipeReservation::create(&name)?);
    Ok(())
}

#[test]
fn occupied_endpoint_is_never_adopted_or_unlinked() -> Result<()> {
    let endpoint = Endpoint::new("collision")?;
    #[cfg(unix)]
    assert!(NativeUnixEndpoint::bind(&endpoint.root.join("ipc.sock")).is_err());
    #[cfg(windows)]
    assert!(NativePipeReservation::create(&Endpoint::name(&endpoint.root)).is_err());
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
    let permissive = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    let refusal = NativeUnixStream::connect(&path, bound(100))
        .err()
        .ok_or("world-access Unix socket admitted")?;
    assert_eq!(refusal.code, IpcNativeErrorCode::UnsafeEndpoint);
    drop(permissive);
    fs::remove_file(&path)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    assert!(NativeUnixEndpoint::bind(&path).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let linked = root.with_extension("linked");
    symlink(&root, &linked)?;
    assert!(NativeUnixEndpoint::bind(&linked.join("ipc.sock")).is_err());
    fs::remove_file(linked)?;
    let foreign_path = root.join("foreign.sock");
    let foreign = UnixListener::bind(&foreign_path)?;
    fs::set_permissions(&foreign_path, fs::Permissions::from_mode(0o600))?;
    symlink(&foreign_path, &path)?;
    assert!(NativeUnixStream::connect(&path, bound(100)).is_err());
    assert!(NativeUnixEndpoint::bind(&path).is_err());
    assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
    fs::remove_file(&path)?;
    drop(foreign);
    fs::remove_file(foreign_path)?;
    let foreign = UnixListener::bind(&path)?;
    assert!(NativeUnixEndpoint::bind(&path).is_err());
    drop(foreign);
    fs::remove_file(path)?;
    fs::remove_dir(root)?;
    Ok(())
}
