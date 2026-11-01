//! Real native readers, with NSS changed only inside dedicated child processes.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use se_proc::NativeStateFiles;
use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
fn child(root: &Path, mode: &str) -> Result {
    let output = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "ancestor_proof_child"])
        .env("SE_ANCESTOR_PROOF_ROOT", root)
        .env("SE_ANCESTOR_PROOF_MODE", mode)
        .env("SE_ANCESTOR_NSS_CONTROL", root.join("control"))
        .env("LD_PRELOAD", root.join("account-switch.so"))
        .output()?;
    assert!(output.status.success(), "{mode}: {output:?}");
    Ok(())
}
#[test]
#[ignore = "dedicated NSS boundary child invoked by process_local_ancestor_proof"]
fn ancestor_proof_child() -> Result {
    let root = std::env::var_os("SE_ANCESTOR_PROOF_ROOT").ok_or("missing root")?;
    let root = Path::new(&root);
    let parent = root.join("ancestor");
    let state = parent.join("state");
    if std::env::var("SE_ANCESTOR_PROOF_MODE")? == "fresh" {
        let error = NativeStateFiles::open(&state)
            .err()
            .ok_or("fresh process reused another process's account proof")?;
        assert_eq!(error.source.and_then(|e| e.raw_os_error()), Some(libc::EIO));
        return Ok(());
    }
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o775))?;
    let files = NativeStateFiles::create(&state)?;
    // Creating state changes the ancestor clock; establish its current epoch.
    assert!(files.readback(&state.join("missing"))?.is_none());
    fs::write(root.join("control"), b"1")?;
    // An unchanged ancestor reuses only its completed process-local NSS proof.
    assert!(files.readback(&state.join("missing"))?.is_none());
    assert!(
        NativeStateFiles::open(&state)?
            .readback(&state.join("missing"))?
            .is_none()
    );
    child(root, "fresh")?;
    // The final private root never inherits the ancestor exception.
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755))?;
    assert!(NativeStateFiles::open(&state).is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    // World-write still refuses even when this inode has a completed proof.
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777))?;
    assert!(files.readback(&state.join("missing")).is_err());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o775))?;
    // Restoring mode does not restore the old epoch: fresh unreadable NSS refuses.
    let error = files
        .readback(&state.join("missing"))
        .err()
        .ok_or("changed ancestor reused an old account proof")?;
    assert_eq!(error.source.and_then(|e| e.raw_os_error()), Some(libc::EIO));
    // A failed proof is never cached as either success or permanent failure.
    fs::write(root.join("control"), b"0")?;
    assert!(files.readback(&state.join("missing"))?.is_none());
    Ok(())
}
#[test]
fn process_local_ancestor_proof() -> Result {
    let root = std::env::temp_dir().join(format!("se-ancestor-proof-{}", std::process::id()));
    assert!(!root.exists(), "preserve an existing fixture");
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    fs::write(root.join("control"), b"0")?;
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(root.join("account-switch.so"))
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/ancestor_account_switch.c"))
        .arg("-ldl")
        .output()?;
    assert!(
        output.status.success(),
        "native fixture compilation: {output:?}"
    );
    child(&root, "warm")?;
    fs::remove_dir(root.join("ancestor/state"))?;
    fs::remove_dir(root.join("ancestor"))?;
    fs::remove_file(root.join("control"))?;
    fs::remove_file(root.join("account-switch.so"))?;
    fs::remove_dir(root)?;
    Ok(())
}
