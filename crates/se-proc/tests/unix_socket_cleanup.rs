//! Real pathname custody while the caller retains its exclusive runtime lease.
#![cfg(unix)]
use se_proc::native_ipc::*;
use std::{
    error::Error,
    fs::{self, File, Permissions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
            net::UnixListener,
        },
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(2),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
struct Fixture {
    root: PathBuf,
    _lease: File,
    _root_owner: cleanup_directory::PrivateDirectory,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "se-cleanup-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&root)?;
        let root_owner = cleanup_directory::PrivateDirectory::for_case(root.clone());
        fs::set_permissions(&root, Permissions::from_mode(0o700))?;
        let lease = File::create(root.join("runtime.lock"))?;
        // SAFETY: a live owned file descriptor; this fixture retains it through cleanup.
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            root,
            _lease: lease,
            _root_owner: root_owner,
        })
    }
    fn socket(&self) -> PathBuf {
        self.root.join("runtime.sock")
    }
    fn listen(&self) -> Result<UnixListener> {
        let listener = UnixListener::bind(self.socket())?;
        fs::set_permissions(self.socket(), Permissions::from_mode(0o600))?;
        Ok(listener)
    }
    fn stale(&self) -> Result {
        drop(self.listen()?);
        Ok(())
    }
    fn observe(&self) -> Result<NativeUnixSocketCleanup> {
        NativeUnixSocketCleanup::observe(&self.socket(), &bound())?
            .ok_or("stale socket reported absent".into())
    }
    fn close(self) -> Result {
        drop(self._lease);
        self._root_owner.finish(Ok(()))
    }
}
#[test]
fn absent_and_stale_are_distinct_and_only_the_observed_socket_is_removed() -> Result {
    let f = Fixture::new()?;
    assert!(NativeUnixSocketCleanup::observe(&f.socket(), &bound())?.is_none());
    f.stale()?;
    let original = fs::symlink_metadata(f.socket())?;
    f.observe()?.compare_remove(&bound())?;
    assert!(!f.socket().try_exists()?);
    assert!(f.root.join("runtime.lock").is_file());
    assert_ne!(original.ino(), 0);
    f.close()
}
#[test]
fn a_live_unidentified_listener_is_preserved_and_receives_no_application_bytes() -> Result {
    let f = Fixture::new()?;
    let listener = f.listen()?;
    let original = fs::symlink_metadata(f.socket())?;
    assert_eq!(
        NativeUnixSocketCleanup::observe(&f.socket(), &bound())
            .err()
            .ok_or("removed live listener")?
            .code,
        IpcNativeErrorCode::AlreadyExists
    );
    let (mut probe, _) = listener.accept()?;
    probe.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let received = loop {
        match probe.read(&mut [0; 1]) {
            Ok(count) => break count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cleanup probe did not close",
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    };
    assert_eq!(received, 0, "cleanup probe sent application bytes");
    assert_eq!(fs::symlink_metadata(f.socket())?.ino(), original.ino());
    drop(listener);
    f.observe()?.compare_remove(&bound())?;
    f.close()
}
#[test]
fn replacement_socket_and_replacement_parent_are_never_removed() -> Result {
    let f = Fixture::new()?;
    f.stale()?;
    let observed = f.observe()?;
    fs::rename(f.socket(), f.root.join("old.sock"))?;
    f.stale()?;
    let replacement = fs::symlink_metadata(f.socket())?.ino();
    assert_eq!(
        observed
            .compare_remove(&bound())
            .err()
            .ok_or("removed replacement socket")?
            .code,
        IpcNativeErrorCode::PeerChanged
    );
    assert_eq!(fs::symlink_metadata(f.socket())?.ino(), replacement);
    let observed = f.observe()?;
    let moved = f.root.with_extension("moved");
    fs::rename(&f.root, &moved)?;
    fs::create_dir(&f.root)?;
    fs::set_permissions(&f.root, Permissions::from_mode(0o700))?;
    f.stale()?;
    assert_eq!(
        observed
            .compare_remove(&bound())
            .err()
            .ok_or("removed socket from replacement parent")?
            .code,
        IpcNativeErrorCode::PeerChanged
    );
    assert!(fs::symlink_metadata(f.socket()).is_ok());
    assert!(fs::symlink_metadata(moved.join("runtime.sock")).is_ok());
    fs::remove_file(f.socket())?;
    fs::remove_dir(&f.root)?;
    fs::rename(moved, &f.root)?;
    fs::remove_file(f.root.join("old.sock"))?;
    f.observe()?.compare_remove(&bound())?;
    f.close()
}
#[test]
fn unknown_path_kinds_links_and_unprotected_sockets_refuse_without_repair() -> Result {
    let f = Fixture::new()?;
    fs::write(f.socket(), b"unrelated work")?;
    assert!(NativeUnixSocketCleanup::observe(&f.socket(), &bound()).is_err());
    assert_eq!(fs::read(f.socket())?, b"unrelated work");
    fs::rename(f.socket(), f.root.join("work"))?;
    symlink(f.root.join("work"), f.socket())?;
    assert!(NativeUnixSocketCleanup::observe(&f.socket(), &bound()).is_err());
    assert_eq!(fs::read(f.socket())?, b"unrelated work");
    fs::remove_file(f.socket())?;
    f.stale()?;
    fs::set_permissions(f.socket(), Permissions::from_mode(0o666))?;
    assert!(NativeUnixSocketCleanup::observe(&f.socket(), &bound()).is_err());
    assert_eq!(fs::symlink_metadata(f.socket())?.mode() & 0o777, 0o666);
    fs::set_permissions(f.socket(), Permissions::from_mode(0o600))?;
    fs::hard_link(f.socket(), f.root.join("linked.sock"))?;
    assert!(NativeUnixSocketCleanup::observe(&f.socket(), &bound()).is_err());
    assert_eq!(fs::symlink_metadata(f.socket())?.nlink(), 2);
    fs::remove_file(f.root.join("linked.sock"))?;
    f.observe()?.compare_remove(&bound())?;
    fs::remove_file(f.root.join("work"))?;
    f.close()
}
#[test]
fn changed_protection_deadline_and_cancellation_preserve_the_socket() -> Result {
    let f = Fixture::new()?;
    f.stale()?;
    let observed = f.observe()?;
    fs::set_permissions(&f.root, Permissions::from_mode(0o755))?;
    assert!(observed.compare_remove(&bound()).is_err());
    assert!(fs::symlink_metadata(f.socket()).is_ok());
    fs::set_permissions(&f.root, Permissions::from_mode(0o700))?;
    for cancelled in [false, true] {
        let observed = f.observe()?;
        let mut stopped = bound();
        let expected = if cancelled {
            stopped.cancelled.store(true, Ordering::Release);
            IpcNativeErrorCode::Cancelled
        } else {
            stopped.deadline = Instant::now();
            IpcNativeErrorCode::TimedOut
        };
        assert_eq!(
            observed
                .compare_remove(&stopped)
                .err()
                .ok_or("removed after bound ended")?
                .code,
            expected
        );
        assert_eq!(
            NativeUnixSocketCleanup::observe(&f.socket(), &stopped)
                .err()
                .ok_or("observed after bound ended")?
                .code,
            expected
        );
        assert!(fs::symlink_metadata(f.socket()).is_ok());
    }
    f.observe()?.compare_remove(&bound())?;
    f.close()
}

#[test]
#[ignore = "run explicitly as root to create a real foreign-owned socket"]
fn foreign_owned_socket_refuses_without_changing_ownership_or_identity() -> Result {
    // SAFETY: geteuid has no pointer arguments or mutation.
    let uid = unsafe { libc::geteuid() };
    assert_eq!(uid, 0, "foreign-owner fixture requires root");
    let f = Fixture::new()?;
    f.stale()?;
    let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
        f.socket().as_os_str(),
    ))?;
    // SAFETY: a nul-terminated path to this test's own socket only.
    if unsafe { libc::chown(name.as_ptr(), 65534, 65534) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let original = fs::symlink_metadata(f.socket())?;
    assert_eq!(original.uid(), 65534);
    assert_eq!(
        NativeUnixSocketCleanup::observe(&f.socket(), &bound())
            .err()
            .ok_or("foreign-owned socket accepted")?
            .code,
        IpcNativeErrorCode::UnsafeEndpoint
    );
    let retained = fs::symlink_metadata(f.socket())?;
    assert_eq!(
        (retained.uid(), retained.ino(), retained.mode()),
        (original.uid(), original.ino(), original.mode())
    );
    fs::remove_file(f.socket())?;
    f.close()
}
