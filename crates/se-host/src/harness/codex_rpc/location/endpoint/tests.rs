use super::*;
use std::os::unix::{fs::symlink, net::UnixListener};
struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    record: PathBuf,
    target: PathBuf,
    value: Record,
}
impl Fixture {
    fn new(alias: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "e-{}",
            se_types::hex_lower(&{
                let mut nonce = [0u8; 4];
                se_proc::fill_entropy(&mut nonce).unwrap();
                nonce
            })
        ));
        se_proc::NativeStateFiles::create(&root).unwrap();
        let listen = root.join("listen");
        se_proc::NativeStateFiles::create(&listen).unwrap();
        let parent = private_parent(&listen).unwrap();
        let socket = listen.join("s");
        let target = if alias {
            let directory = root.join(format!("codex-daemon-{}", parent.uid()));
            se_proc::NativeStateFiles::create(&directory).unwrap();
            directory.join(se_types::hex_lower(&Sha256::digest(
                socket.as_os_str().as_bytes(),
            )))
        } else {
            socket.clone()
        };
        let listener = UnixListener::bind(&target).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        if alias {
            symlink(&target, &socket).unwrap();
        }
        drop(listener);
        let value = Record {
            session: se_types::SessionId::from_parts(1_700_000_000_000, [1; 10]).unwrap(),
            socket: NativePath::from_local(socket.clone()).unwrap(),
            device: parent.dev(),
            inode: parent.ino(),
        };
        let record = root.join("codex-runtime.json");
        let files = se_proc::NativeStateFiles::open(&root).unwrap();
        let mut staging = files.create_staging(&root).unwrap();
        staging
            .file
            .write_all(&serde_json::to_vec(&value).unwrap())
            .unwrap();
        drop(staging.file);
        files.publish_no_replace(&staging.path, &record).unwrap();
        Self {
            root,
            socket,
            record,
            target,
            value,
        }
    }
    fn cleanup(&self) {
        // All names were created here; never recurse or follow links.
        for path in [
            &self.socket,
            &self.target,
            &sidecar(&self.record),
            &self.record,
        ] {
            if metadata(path).unwrap().is_some() {
                std::fs::remove_file(path).unwrap();
            }
        }
        if self.target != self.socket {
            std::fs::remove_dir(self.target.parent().unwrap()).unwrap();
        }
        std::fs::remove_dir(self.socket.parent().unwrap()).unwrap();
        std::fs::remove_dir(&self.root).unwrap();
    }
}
#[test]
fn direct_and_stock_alias_are_pinned_and_retired_without_removing_vendor_parent() {
    for alias in [false, true] {
        let f = Fixture::new(alias);
        prepare(&f.socket, &f.record, &f.value.session).unwrap();
        prepare(&f.socket, &f.record, &f.value.session).unwrap();
        retire(&f.socket, &f.record, &f.value).unwrap();
        assert!(metadata(&f.socket).unwrap().is_none());
        assert!(metadata(&f.target).unwrap().is_none());
        assert!(f.target.parent().unwrap().is_dir());
        f.cleanup();
    }
}
#[test]
fn substituted_socket_or_non_stock_alias_refuses_without_removing_the_leaf() {
    let f = Fixture::new(true);
    prepare(&f.socket, &f.record, &f.value.session).unwrap();
    // Keep the displaced inode allocated, preventing inode reuse.
    let displaced = f.target.with_extension("original");
    std::fs::rename(&f.target, &displaced).unwrap();
    let listener = UnixListener::bind(&f.target).unwrap();
    assert!(retire(&f.socket, &f.record, &f.value).is_err());
    assert!(f.target.exists());
    drop(listener);
    std::fs::remove_file(&f.target).unwrap();
    std::fs::rename(displaced, &f.target).unwrap();
    retire(&f.socket, &f.record, &f.value).unwrap();
    f.cleanup();
    let f = Fixture::new(true);
    std::fs::remove_file(&f.socket).unwrap();
    symlink(f.target.with_extension("foreign"), &f.socket).unwrap();
    assert!(prepare(&f.socket, &f.record, &f.value.session).is_err());
    assert!(retire(&f.socket, &f.record, &f.value).is_err());
    assert!(metadata(&f.socket).unwrap().is_some());
    assert!(f.target.exists());
    f.cleanup();
}
#[test]
fn failed_readiness_cleans_owned_alias_after_vendor_removes_target() {
    let f = Fixture::new(true);
    std::fs::remove_file(&f.target).unwrap();
    retire(&f.socket, &f.record, &f.value).unwrap();
    assert!(metadata(&f.socket).unwrap().is_none());
    assert!(f.target.parent().unwrap().is_dir());
    f.cleanup();
}
