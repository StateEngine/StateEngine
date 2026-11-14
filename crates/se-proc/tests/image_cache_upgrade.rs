//! A persisted digest must not hide an ordinary executable upgrade in a fresh process.
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_proc::{NativeStateFiles, native_ipc::*};
use se_types::Sha256;
use sha2::{Digest, Sha256 as Hasher};
use std::{
    error::Error,
    fs::{self, File, FileTimes, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn digest(path: &Path) -> Result<Sha256> {
    let mut file = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(Sha256::from_bytes(hasher.finalize().into()))
}
fn child(image: &Path, root: &Path, mode: &str, published: Sha256, actual: Sha256) -> Result<()> {
    let output = Command::new(image)
        .args(["--ignored", "--exact", "image_upgrade_child"])
        .env("SE_UPGRADE_ROOT", root)
        .env("SE_UPGRADE_MODE", mode)
        .env("SE_UPGRADE_PUBLISHED", serde_json::to_string(&published)?)
        .env("SE_UPGRADE_ACTUAL", serde_json::to_string(&actual)?)
        .output_executable()?;
    assert!(output.status.success(), "{mode}: {output:?}");
    Ok(())
}
#[test]
#[ignore = "fresh-process helper invoked by persisted_image_hint_detects_upgrade"]
fn image_upgrade_child() -> Result<()> {
    let root = std::env::var_os("SE_UPGRADE_ROOT").ok_or("missing root")?;
    let root = Path::new(&root);
    let published: Sha256 = serde_json::from_str(&std::env::var("SE_UPGRADE_PUBLISHED")?)?;
    let actual: Sha256 = serde_json::from_str(&std::env::var("SE_UPGRADE_ACTUAL")?)?;
    if std::env::var("SE_UPGRADE_MODE")? == "publish" {
        publish_image_cache(root, published, &bound())?;
    } else {
        assert_eq!(
            restore_image_cache(root, published, &bound())?,
            ImageCacheRead::Current
        );
    }
    let peer = observe_ipc_self_bounded(&bound())?;
    assert_eq!(peer.pid(), std::process::id());
    assert_eq!(peer.image_sha256(), actual);
    Ok(())
}
#[test]
fn persisted_image_hint_detects_upgrade() -> Result<()> {
    let _root_owner = cleanup_directory::private_case_directory()?;
    let root = _root_owner.to_path_buf();
    let files = NativeStateFiles::create(&root)?;
    let image = root.join(if cfg!(windows) {
        "original.exe"
    } else {
        "original"
    });
    fs::copy(std::env::current_exe()?, &image)?;
    let mut held = OpenOptions::new().read(true).write(true).open(&image)?;
    held.seek(SeekFrom::End(0))?;
    held.write_all(b"stateengine-cache-upgrade-A")?;
    held.sync_all()?;
    let initial_time = held.metadata()?.modified()?;
    let original = digest(&image)?;
    // Close every writable image handle before starting the executable.
    drop(held);
    child(&image, &root, "publish", original, original)?;
    let cache_path = root.join("ipc-image-cache.json");
    let publication = fs::read(&cache_path)?;

    // Same native identity and size, changed content and modification clock.
    let mut held = OpenOptions::new().write(true).open(&image)?;
    held.seek(SeekFrom::End(-1))?;
    held.write_all(b"B")?;
    held.set_times(FileTimes::new().set_modified(initial_time + Duration::from_secs(2)))?;
    held.sync_all()?;
    drop(held);
    let upgraded = digest(&image)?;
    assert_ne!(upgraded, original);
    child(&image, &root, "restore", original, upgraded)?;

    // A replacement inode/file ID must also miss, even with the old size/clock.
    let replacement = root.join(if cfg!(windows) {
        "replacement.exe"
    } else {
        "replacement"
    });
    fs::copy(&image, &replacement)?;
    File::options()
        .write(true)
        .open(&replacement)?
        .set_times(FileTimes::new().set_modified(initial_time))?;
    child(&replacement, &root, "restore", original, upgraded)?;
    assert_eq!(
        fs::read(&cache_path)?,
        publication,
        "readers never republish hints"
    );
    drop(files);
    fs::remove_file(replacement)?;
    fs::remove_file(image)?;
    fs::remove_file(cache_path)?;
    fs::remove_dir(root)?;
    _root_owner.finish(Ok(()))
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
