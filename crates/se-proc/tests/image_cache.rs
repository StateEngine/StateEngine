use se_proc::{NativeStateFiles, native_ipc::*};
use se_types::Sha256;
use std::{
    error::Error,
    fs,
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
fn restore_child(root: &Path, digest: Sha256) -> Result<()> {
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "restored_hint_keeps_native_self_identity",
        ])
        .env("SE_IMAGE_CACHE_TEST_ROOT", root)
        .env(
            "SE_IMAGE_CACHE_TEST_DIGEST",
            serde_json::to_string(&digest)?,
        )
        .output_executable()?;
    assert!(output.status.success(), "child: {output:?}");
    Ok(())
}
#[test]
#[ignore = "child process invoked by protected_cache_contract"]
fn restored_hint_keeps_native_self_identity() -> Result<()> {
    let root = std::env::var_os("SE_IMAGE_CACHE_TEST_ROOT").ok_or("missing test root")?;
    let digest: Sha256 = serde_json::from_str(&std::env::var("SE_IMAGE_CACHE_TEST_DIGEST")?)?;
    assert_eq!(
        restore_image_cache(Path::new(&root), digest, &bound())?,
        ImageCacheRead::Current
    );
    let observed = observe_ipc_self_bounded(&bound())?;
    assert_eq!(observed.pid(), std::process::id());
    assert_eq!(observed.image_sha256(), digest);
    Ok(())
}
#[test]
fn protected_cache_contract() -> Result<()> {
    let root = std::env::temp_dir().join(format!("se-image-cache-{}", std::process::id()));
    assert!(!root.exists(), "preserve an existing fixture");
    let files = NativeStateFiles::create(&root)?;
    let digest = observe_ipc_self_bounded(&bound())?.image_sha256();
    assert_eq!(
        restore_image_cache(&root, digest, &bound())?,
        ImageCacheRead::Absent
    );
    publish_image_cache(&root, digest, &bound())?;
    restore_child(&root, digest)?;
    // The second publication exercises native atomic replacement of an old hint.
    publish_image_cache(&root, digest, &bound())?;
    restore_child(&root, digest)?;
    let path = root.join("ipc-image-cache.json");
    let original = fs::read(&path)?;
    assert!(original.len() <= 4096);
    let other = Sha256::from_bytes(if digest == Sha256::from_bytes([0; 32]) {
        [1; 32]
    } else {
        [0; 32]
    });
    assert_eq!(
        restore_image_cache(&root, other, &bound())?,
        ImageCacheRead::Stale
    );
    let cancelled = bound();
    cancelled
        .cancelled
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        restore_image_cache(&root, digest, &cancelled)
            .err()
            .ok_or("cancelled restore succeeded")?
            .code,
        IpcNativeErrorCode::Cancelled
    );
    fs::write(&path, b"{bad json}")?;
    assert_eq!(
        restore_image_cache(&root, digest, &bound())
            .err()
            .ok_or("malformed cache admitted")?
            .code,
        IpcNativeErrorCode::Unreadable
    );
    fs::write(&path, vec![b' '; 4097])?;
    assert_eq!(
        restore_image_cache(&root, digest, &bound())
            .err()
            .ok_or("oversize cache admitted")?
            .code,
        IpcNativeErrorCode::Unreadable
    );
    fs::write(&path, &original)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(restore_image_cache(&root, digest, &bound()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let saved = root.join("saved-cache");
        fs::rename(&path, &saved)?;
        symlink(&saved, &path)?;
        assert!(restore_image_cache(&root, digest, &bound()).is_err());
        fs::remove_file(&path)?;
        fs::rename(saved, &path)?;
    }
    drop(files);
    fs::remove_file(path)?;
    // Refuse unexpected leftovers rather than deleting outside the known fixture.
    fs::remove_dir(root)?;
    Ok(())
}

/// Protects: executable hints cannot hide same-inode rewrites restoring size and mtime.
#[test]
fn restored_modification_time_does_not_reuse_old_digest() -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let root = std::env::temp_dir().join(format!("se-image-ctime-{}", std::process::id()));
    assert!(!root.exists(), "preserve an existing fixture");
    fs::create_dir(&root)?;
    let cache = root.join("cache");
    let files = NativeStateFiles::create(&cache)?;
    let image = root.join(if cfg!(windows) { "probe.exe" } else { "probe" });
    fs::copy(std::env::current_exe()?, &image)?;
    fs::OpenOptions::new()
        .append(true)
        .open(&image)?
        .write_all(&[0; 4096])?;
    let digest_path = root.join("digest.json");
    let run = |action: &str| -> Result<()> {
        let output = Command::new(&image)
            .args(["--ignored", "--exact", "changed_image_child"])
            .env("SE_IMAGE_CTIME_ROOT", &cache)
            .env("SE_IMAGE_CTIME_DIGEST", &digest_path)
            .env("SE_IMAGE_CTIME_ACTION", action)
            .output_executable()?;
        assert!(output.status.success(), "{action}: {output:?}");
        Ok(())
    };
    run("publish")?;
    let metadata = fs::metadata(&image)?;
    let mut file = fs::OpenOptions::new().write(true).open(&image)?;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(&[1])?;
    file.sync_all()?;
    file.set_modified(metadata.modified()?)?;
    drop(file);
    assert_eq!(fs::metadata(&image)?.len(), metadata.len());
    assert_eq!(fs::metadata(&image)?.modified()?, metadata.modified()?);
    run("restore")?;
    drop(files);
    fs::remove_file(cache.join("ipc-image-cache.json"))?;
    fs::remove_dir(cache)?;
    fs::remove_file(image)?;
    fs::remove_file(digest_path)?;
    fs::remove_dir(root)?;
    Ok(())
}
/// Protects: child-side observation uses public native proof after a real executable rewrite.
#[test]
#[ignore = "child process invoked by restored_modification_time_does_not_reuse_old_digest"]
fn changed_image_child() -> Result<()> {
    let root = std::env::var_os("SE_IMAGE_CTIME_ROOT").ok_or("missing cache root")?;
    let digest_path = std::env::var_os("SE_IMAGE_CTIME_DIGEST").ok_or("missing digest path")?;
    let root = Path::new(&root);
    match std::env::var("SE_IMAGE_CTIME_ACTION")?.as_str() {
        "publish" => {
            let digest = observe_ipc_self_bounded(&bound())?.image_sha256();
            publish_image_cache(root, digest, &bound())?;
            fs::write(digest_path, serde_json::to_vec(&digest)?)?;
        }
        "restore" => {
            let old: Sha256 = serde_json::from_slice(&fs::read(digest_path)?)?;
            assert_eq!(
                restore_image_cache(root, old, &bound())?,
                ImageCacheRead::Current
            );
            assert_ne!(
                observe_ipc_self_bounded(&bound())?.image_sha256(),
                old,
                "a same-file rewrite restored to its old mtime reused the stale proof"
            );
        }
        _ => return Err("unknown child action".into()),
    }
    Ok(())
}

/// Protects: uploaded copies get a separate hint, without replacing the host's
/// hint or allowing restored mtime to hide a same-file content change.
#[test]
fn remote_image_hint_keeps_host_hint_and_changed_file_proof() -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let root = std::env::temp_dir().join(format!("se-remote-cache-{}", std::process::id()));
    let files = NativeStateFiles::create(&root)?;
    let expected = observe_ipc_self_bounded(&bound())?.image_sha256();
    publish_image_cache(&root, expected, &bound())?;
    let host = fs::read(root.join("ipc-image-cache.json"))?;
    let image = root.join(if cfg!(windows) {
        "uploaded.exe"
    } else {
        "uploaded"
    });
    fs::copy(std::env::current_exe()?, &image)?;
    let run = |mode: &str| -> Result<()> {
        let output = Command::new(&image)
            .args(["--ignored", "--exact", "remote_image_hint_child"])
            .env("SE_REMOTE_CACHE_ROOT", &root)
            .env("SE_REMOTE_CACHE_DIGEST", serde_json::to_string(&expected)?)
            .env("SE_REMOTE_CACHE_MODE", mode)
            .output_executable()?;
        assert!(output.status.success(), "{mode}: {output:?}");
        Ok(())
    };
    run("publish")?;
    assert_eq!(fs::read(root.join("ipc-image-cache.json"))?, host);
    let remote_path = root.join("ipc-remote-image-cache.json");
    let remote = fs::read(&remote_path)?;
    assert!(remote.len() <= 4096);
    assert_ne!(
        remote, host,
        "uploaded file identity was not independently observed"
    );
    run("restore")?;
    let metadata = fs::metadata(&image)?;
    let mut file = fs::OpenOptions::new().read(true).write(true).open(&image)?;
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0];
    file.read_exact(&mut last)?;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(&[last[0] ^ 1])?;
    file.sync_all()?;
    file.set_modified(metadata.modified()?)?;
    drop(file);
    assert_eq!(fs::metadata(&image)?.len(), metadata.len());
    assert_eq!(fs::metadata(&image)?.modified()?, metadata.modified()?);
    // Different bytes cannot publish a hint tied to the incumbent's digest.
    run("different-image")?;
    assert_eq!(fs::read(&remote_path)?, remote);
    fs::write(&remote_path, b"{broken")?;
    assert!(restore_remote_image_cache(&root, expected, &bound()).is_err());
    fs::write(&remote_path, vec![b' '; 4097])?;
    assert!(restore_remote_image_cache(&root, expected, &bound()).is_err());
    let cancelled = bound();
    cancelled
        .cancelled
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(restore_remote_image_cache(&root, expected, &cancelled).is_err());
    drop(files);
    fs::remove_file(root.join("ipc-image-cache.json"))?;
    fs::remove_file(remote_path)?;
    fs::remove_file(image)?;
    fs::remove_dir(root)?;
    Ok(())
}
#[test]
#[ignore = "fresh-process helper invoked by remote_image_hint_keeps_host_hint_and_changed_file_proof"]
fn remote_image_hint_child() -> Result<()> {
    let root = std::env::var_os("SE_REMOTE_CACHE_ROOT").ok_or("missing remote hint home")?;
    let root = Path::new(&root);
    let expected: Sha256 = serde_json::from_str(&std::env::var("SE_REMOTE_CACHE_DIGEST")?)?;
    match std::env::var("SE_REMOTE_CACHE_MODE")?.as_str() {
        "publish" => assert_eq!(
            publish_remote_image_cache(root, expected, &bound())?,
            ImageCacheRead::Current
        ),
        "restore" => {
            assert_eq!(
                restore_image_cache(root, expected, &bound())?,
                ImageCacheRead::Current
            );
            assert_eq!(
                restore_remote_image_cache(root, expected, &bound())?,
                ImageCacheRead::Current
            );
            assert_eq!(observe_ipc_self_bounded(&bound())?.image_sha256(), expected);
        }
        "different-image" => {
            assert_eq!(
                restore_remote_image_cache(root, expected, &bound())?,
                ImageCacheRead::Current
            );
            assert_ne!(observe_ipc_self_bounded(&bound())?.image_sha256(), expected);
            assert_eq!(
                publish_remote_image_cache(root, expected, &bound())?,
                ImageCacheRead::Stale
            );
        }
        _ => return Err("unknown remote hint action".into()),
    }
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
