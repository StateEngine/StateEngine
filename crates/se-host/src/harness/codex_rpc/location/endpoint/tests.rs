use super::*;
use std::os::unix::{fs::symlink, net::UnixListener};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    record: PathBuf,
    target: PathBuf,
    value: Record,
}
impl Fixture {
    fn new(alias: bool) -> Check<Self> {
        let root = std::env::temp_dir().join(format!(
            "e-{}",
            se_types::hex_lower(&{
                let mut nonce = [0u8; 4];
                se_proc::fill_entropy(&mut nonce)?;
                nonce
            })
        ));
        se_proc::NativeStateFiles::create(&root)?;
        let listen = root.join("listen");
        se_proc::NativeStateFiles::create(&listen)?;
        let parent = private_parent(&listen)?;
        let socket = listen.join("s");
        let target = if alias {
            let directory = root.join(format!("codex-daemon-{}", parent.uid()));
            se_proc::NativeStateFiles::create(&directory)?;
            directory.join(se_types::hex_lower(&Sha256::digest(
                socket.as_os_str().as_bytes(),
            )))
        } else {
            socket.clone()
        };
        let listener = UnixListener::bind(&target)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
        if alias {
            symlink(&target, &socket)?;
        }
        drop(listener);
        let value = Record {
            session: se_types::SessionId::from_parts(1_700_000_000_000, [1; 10])?,
            socket: NativePath::from_local(socket.clone())?,
            device: parent.dev(),
            inode: parent.ino(),
        };
        let record = root.join("codex-runtime.json");
        let files = se_proc::NativeStateFiles::open(&root)?;
        let mut staging = files.create_staging(&root)?;
        staging.file.write_all(&serde_json::to_vec(&value)?)?;
        drop(staging.file);
        files.publish_no_replace(&staging.path, &record)?;
        Ok(Self {
            root,
            socket,
            record,
            target,
            value,
        })
    }
    fn cleanup(&self) -> Check {
        // All names were created here; never recurse or follow links.
        for path in [
            &self.socket,
            &self.target,
            &sidecar(&self.record),
            &self.record,
        ] {
            if metadata(path)?.is_some() {
                std::fs::remove_file(path)?;
            }
        }
        if self.target != self.socket {
            std::fs::remove_dir(self.target.parent().ok_or("owned endpoint parent absent")?)?;
        }
        std::fs::remove_dir(self.socket.parent().ok_or("owned endpoint parent absent")?)?;
        std::fs::remove_dir(&self.root)?;
        Ok(())
    }
}
#[test]
fn direct_and_stock_alias_are_pinned_and_retired_without_removing_vendor_parent() -> Check {
    for alias in [false, true] {
        let f = Fixture::new(alias)?;
        prepare(&f.socket, &f.record, &f.value.session)?;
        assert_eq!(
            CodexHarness::retained_socket(&f.record, &f.value.session)?,
            f.socket
        );
        prepare(&f.socket, &f.record, &f.value.session)?;
        retire(&f.socket, &f.record, &f.value)?;
        assert!(metadata(&f.socket)?.is_none());
        assert!(metadata(&f.target)?.is_none());
        assert!(
            f.target
                .parent()
                .ok_or("owned endpoint parent absent")?
                .is_dir()
        );
        f.cleanup()?;
    }
    Ok(())
}
#[test]
fn recovery_requires_the_original_session_and_endpoint_journal() -> Check {
    let f = Fixture::new(false)?;
    assert!(CodexHarness::retained_socket(&f.record, &f.value.session).is_err());
    assert!(metadata(&sidecar(&f.record))?.is_none());
    prepare(&f.socket, &f.record, &f.value.session)?;
    let other = se_types::SessionId::from_parts(1_700_000_000_000, [2; 10])?;
    assert!(CodexHarness::retained_socket(&f.record, &other).is_err());
    let held = f.root.join("original-endpoint");
    std::fs::rename(sidecar(&f.record), &held)?;
    assert!(CodexHarness::retained_socket(&f.record, &f.value.session).is_err());
    assert!(metadata(&sidecar(&f.record))?.is_none());
    std::fs::rename(held, sidecar(&f.record))?;
    retire(&f.socket, &f.record, &f.value)?;
    f.cleanup()
}
#[test]
fn substituted_socket_or_non_stock_alias_refuses_without_removing_the_leaf() -> Check {
    let f = Fixture::new(true)?;
    prepare(&f.socket, &f.record, &f.value.session)?;
    // Keep the displaced inode allocated, preventing inode reuse.
    let displaced = f.target.with_extension("original");
    std::fs::rename(&f.target, &displaced)?;
    let listener = UnixListener::bind(&f.target)?;
    assert!(retire(&f.socket, &f.record, &f.value).is_err());
    assert!(f.target.exists());
    drop(listener);
    std::fs::remove_file(&f.target)?;
    std::fs::rename(displaced, &f.target)?;
    retire(&f.socket, &f.record, &f.value)?;
    f.cleanup()?;
    let f = Fixture::new(true)?;
    std::fs::remove_file(&f.socket)?;
    symlink(f.target.with_extension("foreign"), &f.socket)?;
    assert!(prepare(&f.socket, &f.record, &f.value.session).is_err());
    assert!(retire(&f.socket, &f.record, &f.value).is_err());
    assert!(metadata(&f.socket)?.is_some());
    assert!(f.target.exists());
    f.cleanup()?;
    Ok(())
}
#[test]
fn failed_readiness_cleans_owned_alias_after_vendor_removes_target() -> Check {
    let f = Fixture::new(true)?;
    std::fs::remove_file(&f.target)?;
    retire(&f.socket, &f.record, &f.value)?;
    assert!(metadata(&f.socket)?.is_none());
    assert!(
        f.target
            .parent()
            .ok_or("owned endpoint parent absent")?
            .is_dir()
    );
    f.cleanup()?;
    Ok(())
}
