//! Path selection exercised through native bind/connect and stale custody.
#![cfg(unix)]
use se_proc::native_ipc::*;
#[cfg(target_os = "linux")]
use std::os::unix::{fs::symlink, net::UnixListener};
use std::{
    fs::{self, File, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Home {
    root: PathBuf,
    _lease: File,
}
impl Home {
    fn new() -> Result<Self> {
        let root = PathBuf::from("/tmp").join(format!(
            "se-path-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        private(&root)?;
        let lease = File::create(root.join("runtime.lock"))?;
        lease.try_lock()?;
        Ok(Self {
            root,
            _lease: lease,
        })
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn private(path: &Path) -> Result {
    fs::create_dir(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o700))?;
    Ok(())
}
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(3),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn round_trip(path: &Path) -> Result {
    let endpoint = NativeUnixEndpoint::bind(path)?;
    let mut client = NativeUnixStream::connect(path, bound())?;
    client.write_all(b"selected endpoint")?;
    let (mut server, _) = endpoint.listener().accept()?;
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = [0; 17];
    server.read_exact(&mut bytes)?;
    assert_eq!(&bytes, b"selected endpoint");
    drop(server);
    drop(client);
    endpoint.close()?;
    assert!(!path.try_exists()?);
    Ok(())
}
#[test]
fn state_run_is_private_and_usable_by_the_real_native_consumer() -> Result {
    let h = Home::new()?;
    let paths = UnixSocketPaths::default();
    let expected = paths.expected_path(&h.root)?;
    assert!(!h.root.join("run").try_exists()?);
    let path = paths.prepare(&h.root, &bound())?;
    assert_eq!(path, expected);
    assert_eq!(path, h.root.join("run/runtime.sock"));
    assert_eq!(
        fs::metadata(path.parent().ok_or("parent")?)?.mode() & 0o7777,
        0o700
    );
    assert!(!h.root.join("runtime.sock").try_exists()?);
    round_trip(&path)
}
#[test]
fn expected_paths_are_pure_even_when_the_home_does_not_exist() -> Result {
    let h = Home::new()?;
    let missing = h.root.join("not-initialized");
    let options = UnixSocketPaths::default();
    assert_eq!(
        options.expected_path(&missing)?,
        missing.join("run/runtime.sock")
    );
    assert!(!missing.try_exists()?);
    assert!(options.expected_path(Path::new("relative-home")).is_err());
    assert!(options.expected_path(&h.root.join("../other")).is_err());
    #[cfg(target_os = "linux")]
    {
        let runtime = h.root.join("x");
        let options = UnixSocketPaths {
            runtime_directory: Some(runtime.clone()),
            temporary_directory: None,
        };
        assert!(
            options
                .expected_path(&missing)?
                .starts_with(runtime.join("stateengine"))
        );
        assert!(!runtime.try_exists()?);
    }
    Ok(())
}
#[test]
fn absent_platform_directories_use_private_short_sockets_for_long_homes() -> Result {
    let h = Home::new()?;
    let first = h.root.join("long-state-home-".repeat(8));
    let second = h.root.join("another-long-home-".repeat(8));
    private(&first)?;
    private(&second)?;
    let options = UnixSocketPaths::default();
    let expected = options.expected_path(&first)?;
    let a = options.prepare(&first, &bound())?;
    let b = options.prepare(&second, &bound())?;
    assert_eq!(a, expected);
    assert_ne!(a, b);
    assert!(!a.starts_with(&h.root));
    assert!(a.as_os_str().as_encoded_bytes().len() < 100);
    let long_temporary = UnixSocketPaths {
        runtime_directory: None,
        temporary_directory: Some(first.clone()),
    };
    assert_eq!(long_temporary.expected_path(&first)?, a);
    let parent = fs::metadata(a.parent().ok_or("parent")?)?;
    assert_eq!(parent.uid(), fs::metadata(&h.root)?.uid());
    assert_eq!(parent.mode() & 0o7777, 0o700);
    round_trip(&a)?;
    round_trip(&b)
}
#[cfg(target_os = "linux")]
#[test]
fn xdg_homes_do_not_collide_and_stale_cleanup_keeps_its_native_checks() -> Result {
    let first = Home::new()?;
    let second = Home::new()?;
    let xdg = first.root.join("xdg");
    private(&xdg)?;
    let options = UnixSocketPaths {
        runtime_directory: Some(xdg.clone()),
        temporary_directory: None,
    };
    let a = options.prepare(&first.root, &bound())?;
    let b = options.prepare(&second.root, &bound())?;
    assert_eq!(a, options.expected_path(&first.root)?);
    assert_eq!(b, options.expected_path(&second.root)?);
    assert_ne!(a, b);
    assert_eq!(a.parent(), Some(xdg.join("stateengine").as_path()));
    round_trip(&a)?;
    let stale = UnixListener::bind(&a)?;
    fs::set_permissions(&a, Permissions::from_mode(0o600))?;
    assert_eq!(
        NativeUnixSocketCleanup::observe(&a, &bound())
            .err()
            .ok_or("removed live listener")?
            .code,
        IpcNativeErrorCode::AlreadyExists
    );
    drop(stale);
    NativeUnixSocketCleanup::observe(&a, &bound())?
        .ok_or("stale absent")?
        .compare_remove(&bound())?;
    round_trip(&a)?;
    round_trip(&b)
}
#[cfg(target_os = "linux")]
#[test]
fn a_long_home_can_bind_through_xdg_and_an_overlong_root_is_not_mutated() -> Result {
    let h = Home::new()?;
    let home = h.root.join("long-state-home-".repeat(8));
    private(&home)?;
    let lease = File::create(home.join("runtime.lock"))?;
    lease.try_lock()?;
    let xdg = h.root.join("xdg");
    private(&xdg)?;
    let options = UnixSocketPaths {
        runtime_directory: Some(xdg),
        temporary_directory: None,
    };
    let path = options.prepare(&home, &bound())?;
    assert!(
        home.join("runtime.sock")
            .as_os_str()
            .as_encoded_bytes()
            .len()
            > 108
    );
    round_trip(&path)?;
    let too_long = UnixSocketPaths {
        runtime_directory: Some(home.clone()),
        temporary_directory: None,
    };
    assert!(too_long.prepare(&home, &bound()).is_err());
    assert!(!home.join("stateengine").try_exists()?);
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn unsafe_xdg_roots_and_linked_runtime_directories_are_preserved() -> Result {
    let h = Home::new()?;
    let xdg = h.root.join("xdg");
    private(&xdg)?;
    let options = UnixSocketPaths {
        runtime_directory: Some(xdg.clone()),
        temporary_directory: None,
    };
    fs::set_permissions(&xdg, Permissions::from_mode(0o770))?;
    assert!(options.prepare(&h.root, &bound()).is_err());
    assert_eq!(fs::metadata(&xdg)?.mode() & 0o7777, 0o770);
    assert!(!xdg.join("stateengine").try_exists()?);
    fs::set_permissions(&xdg, Permissions::from_mode(0o700))?;
    let target = h.root.join("untouched");
    private(&target)?;
    symlink(&target, xdg.join("stateengine"))?;
    assert!(options.prepare(&h.root, &bound()).is_err());
    assert!(
        fs::symlink_metadata(xdg.join("stateengine"))?
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_dir(&target)?.count(), 0);
    Ok(())
}
#[cfg(target_os = "macos")]
#[test]
fn long_mac_home_uses_protected_temporary_leaf_and_a_short_live_socket() -> Result {
    let h = Home::new()?;
    let long = h.root.join("a".repeat(100));
    private(&long)?;
    let options = UnixSocketPaths {
        runtime_directory: None,
        temporary_directory: Some(h.root.clone()),
    };
    let path = options.prepare(&long, &bound())?;
    assert_eq!(path, options.expected_path(&long)?);
    assert!(!path.starts_with(long.join("run")));
    assert!(path.as_os_str().as_encoded_bytes().len() < 104);
    assert_eq!(
        fs::metadata(path.parent().ok_or("parent")?)?.mode() & 0o7777,
        0o700
    );
    round_trip(&path)
}
