//! Protected executable hints must preserve kernel-observed caller and image identity.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;
use se_proc::{NativeStateFiles, native_ipc::*};
use se_types::{BootId, MachineId, ProcessFields, ProcessInstance, Sha256};
use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    num::NonZeroU32,
    os::{
        fd::AsFd,
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
type Check<T = ()> = Result<T, Box<dyn Error>>;
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn instance(peer: &NativeIpcPeer) -> Check<ProcessInstance> {
    Ok(ProcessInstance::from_observation(ProcessFields {
        machine: MachineId::new("native-hint-boundary")?,
        boot: BootId::new("synthetic-boot")?,
        pid: NonZeroU32::new(peer.pid()).ok_or("missing native pid")?,
        started: peer.started().clone(),
        executable: peer.image().clone(),
        argv_sha256: Sha256::from_bytes([0; 32]),
    })?)
}
struct JoinedChild(Child);
impl Drop for JoinedChild {
    fn drop(&mut self) {
        // Closing this owned pipe releases the helper even when an assertion fails.
        drop(self.0.stdin.take());
        let _ = self.0.wait();
    }
}
struct Fixture {
    root: PathBuf,
    image: PathBuf,
    listener: UnixListener,
    _root_owner: cleanup_directory::PrivateDirectory,
}
impl Fixture {
    fn new() -> Check<Self> {
        let root = std::env::temp_dir().join(format!("se-native-hint-{}", std::process::id()));
        fs::create_dir(&root)?;
        let root_owner = cleanup_directory::PrivateDirectory::adopt(root.clone());
        fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        drop(NativeStateFiles::create(&root)?);
        let image = root.join("client");
        fs::copy(std::env::current_exe()?, &image)?;
        let address =
            SocketAddr::from_abstract_name(format!("se-native-hint-{}", std::process::id()))?;
        let listener = UnixListener::bind_addr(&address)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            root,
            image,
            listener,
            _root_owner: root_owner,
        })
    }
    fn exchange(&self, mode: &str, digest: Sha256) -> Check<(NativeIpcPeer, Vec<u8>)> {
        let mut child = JoinedChild(
            Command::new(&self.image)
                .args(["--ignored", "--exact", "native_hint_helper"])
                .env("SE_NATIVE_HINT_ROOT", &self.root)
                .env("SE_NATIVE_HINT_ADDRESS", std::process::id().to_string())
                .env("SE_NATIVE_HINT_MODE", mode)
                .env("SE_NATIVE_HINT_DIGEST", serde_json::to_string(&digest)?)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn_executable()?,
        );
        let deadline = Instant::now() + Duration::from_secs(35);
        let stream = loop {
            match self.listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(status) = child.0.try_wait()? {
                        return Err(format!("helper exited before connecting: {status}").into());
                    }
                    if Instant::now() >= deadline {
                        return Err("helper connection deadline".into());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(35)))?;
        let peer = observe_ipc_peer_bounded(stream.as_fd(), IpcPeerSide::Client, &bound())?;
        let mut line = Vec::new();
        BufReader::new(stream)
            .take(4097)
            .read_until(b'\n', &mut line)?;
        assert!(line.len() <= 4096 && line.last() == Some(&b'\n'));
        let binding = serde_json::from_slice(&line)?;
        drop(child.0.stdin.take());
        assert!(child.0.wait()?.success(), "native helper failed");
        Ok((peer, binding))
    }
    fn close(self) -> Check {
        drop(self.listener);
        fs::remove_file(self.image)?;
        fs::remove_file(self.root.join("ipc-remote-image-cache.json"))?;
        fs::remove_dir(self.root)?;
        Ok(())
    }
}
/// Protects: a restored remote hint never replays the old process or executable proof.
#[test]
fn remote_hint_cannot_replay_a_different_caller_or_replaced_executable() -> Check {
    let f = Fixture::new()?;
    let digest = observe_ipc_self_bounded(&bound())?.image_sha256();
    let (first, claimed) = f.exchange("publish", digest)?;
    assert_eq!(claimed, first.binding());
    assert_eq!(first.image_sha256(), digest);
    let expected = instance(&first)?;
    let cache = fs::read(f.root.join("ipc-remote-image-cache.json"))?;
    let (second, claimed) = f.exchange("restore", digest)?;
    assert_eq!(claimed, second.binding());
    assert_ne!(second.pid(), first.pid());
    assert_ne!(second.binding(), first.binding());
    assert_eq!(
        second
            .verify_instance(&expected, digest)
            .err()
            .ok_or("another caller reused the old process proof")?
            .code,
        IpcNativeErrorCode::PeerChanged
    );
    assert_eq!(fs::read(f.root.join("ipc-remote-image-cache.json"))?, cache);

    // Replace the file at the exact saved pathname after both old callers joined.
    let replacement = f.root.join("replacement");
    fs::copy(std::env::current_exe()?, &replacement)?;
    fs::OpenOptions::new()
        .append(true)
        .open(&replacement)?
        .write_all(b"synthetic executable replacement\n")?;
    fs::rename(replacement, &f.image)?;
    let (replaced, claimed) = f.exchange("restore", digest)?;
    assert_eq!(
        claimed,
        replaced.binding(),
        "self and socket peer proof diverged"
    );
    assert_ne!(
        replaced.image_sha256(),
        digest,
        "restored hint concealed replacement bytes"
    );
    // Keep the new native pid/birth/path, so this refusal isolates the old digest.
    assert_eq!(
        replaced
            .verify_instance(&instance(&replaced)?, digest)
            .err()
            .ok_or("stale image proof admitted")?
            .code,
        IpcNativeErrorCode::PeerChanged
    );
    replaced.verify_instance(&instance(&replaced)?, replaced.image_sha256())?;
    assert_eq!(fs::read(f.root.join("ipc-remote-image-cache.json"))?, cache);
    f.close()
}
/// Protects: unreadable remote hints cannot become authority through a warm image cache.
#[test]
fn unreadable_remote_hint_refuses_after_warming_native_self_proof() -> Check {
    use std::os::unix::fs::{PermissionsExt, symlink};
    // This test has its own process under nextest; distinct names also support libtest.
    let root =
        std::env::temp_dir().join(format!("se-native-hint-unreadable-{}", std::process::id()));
    fs::create_dir(&root)?;
    let _root_owner = cleanup_directory::PrivateDirectory::adopt(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    drop(NativeStateFiles::create(&root)?);
    let digest = observe_ipc_self_bounded(&bound())?.image_sha256();
    assert_eq!(
        publish_remote_image_cache(&root, digest, &bound())?,
        ImageCacheRead::Current
    );
    let path = root.join("ipc-remote-image-cache.json");
    let original = fs::read(&path)?;
    for bytes in [b"{malformed".to_vec(), vec![b' '; 4097]] {
        fs::write(&path, &bytes)?;
        assert_eq!(
            restore_remote_image_cache(&root, digest, &bound())
                .err()
                .ok_or("unreadable hint admitted")?
                .code,
            IpcNativeErrorCode::Unreadable
        );
        assert_eq!(fs::read(&path)?, bytes, "unreadable state was replaced");
    }
    fs::write(&path, &original)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(restore_remote_image_cache(&root, digest, &bound()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let saved = root.join("protected-hint");
    fs::rename(&path, &saved)?;
    symlink(&saved, &path)?;
    assert!(restore_remote_image_cache(&root, digest, &bound()).is_err());
    assert_eq!(fs::read(&saved)?, original);
    fs::remove_file(&path)?;
    fs::remove_file(saved)?;
    fs::remove_dir(root)?;
    Ok(())
}
#[test]
#[ignore = "fresh process invoked by native boundary controls"]
fn native_hint_helper() -> Check {
    let root = std::env::var_os("SE_NATIVE_HINT_ROOT").ok_or("missing fixture root")?;
    let expected: Sha256 = serde_json::from_str(&std::env::var("SE_NATIVE_HINT_DIGEST")?)?;
    let mode = std::env::var("SE_NATIVE_HINT_MODE")?;
    let root = Path::new(&root);
    if mode == "publish" {
        assert_eq!(
            publish_remote_image_cache(root, expected, &bound())?,
            ImageCacheRead::Current
        );
    } else {
        assert_eq!(mode, "restore");
        assert_eq!(
            restore_remote_image_cache(root, expected, &bound())?,
            ImageCacheRead::Current
        );
    }
    let peer = observe_ipc_self_bounded(&bound())?;
    let address = SocketAddr::from_abstract_name(format!(
        "se-native-hint-{}",
        std::env::var("SE_NATIVE_HINT_ADDRESS")?
    ))?;
    let mut stream = UnixStream::connect_addr(&address)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    serde_json::to_writer(&mut stream, &peer.binding())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let _ = std::io::stdin().read(&mut [0]);
    Ok(())
}
