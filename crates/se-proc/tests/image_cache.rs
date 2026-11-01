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
        .output()?;
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
