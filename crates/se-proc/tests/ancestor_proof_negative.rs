//! NSS refusals cannot grant or permanently poison an ancestor proof.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_proc::{NativeStateFiles, StateFileErrorCode};
use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
fn mode(path: &Path, value: u32) -> Result {
    fs::set_permissions(path, fs::Permissions::from_mode(value))?;
    Ok(())
}
#[test]
#[ignore = "dedicated NSS boundary child invoked by negative_proof_and_replaced_directory"]
fn negative_proof_child() -> Result {
    let root = std::env::var_os("SE_NEGATIVE_PROOF_ROOT").ok_or("missing fixture root")?;
    let root = Path::new(&root);
    let parent = root.join("ancestor");
    let state = parent.join("state");
    fs::create_dir(&parent)?;
    mode(&parent, 0o700)?;
    let initial = NativeStateFiles::create(&state)?;
    drop(initial);
    mode(&parent, 0o775)?;
    let control = root.join("control");
    fs::write(&control, b"F")?;
    // NSS supplies a foreign supplemental member. A completed false verdict
    // must refuse again rather than becoming a successful cache entry.
    for _ in 0..2 {
        let error = NativeStateFiles::open(&state)
            .err()
            .ok_or("negative account proof granted an ancestor exception")?;
        assert_eq!(error.code, StateFileErrorCode::LocationUnsafe);
    }
    // The same directory epoch can recover when a later full proof succeeds.
    fs::write(&control, b"0")?;
    let held = NativeStateFiles::open(&state)?;
    assert!(held.readback(&state.join("missing"))?.is_none());
    fs::write(&control, b"1")?;
    assert!(NativeStateFiles::open(&state).is_ok());
    assert!(held.readback(&state.join("missing"))?.is_none());

    // Replace the directory at the same spelling with the same owner/group/mode.
    // Neither a held root nor a fresh reader can reuse the old inode's proof.
    fs::rename(&parent, root.join("retired"))?;
    fs::create_dir(&parent)?;
    mode(&parent, 0o775)?;
    fs::create_dir(&state)?;
    mode(&state, 0o700)?;
    assert!(held.readback(&state.join("missing")).is_err());
    let error = NativeStateFiles::open(&state)
        .err()
        .ok_or("replacement directory inherited a prior account proof")?;
    assert_eq!(error.source.and_then(|e| e.raw_os_error()), Some(libc::EIO));
    fs::write(&control, b"0")?;
    assert!(NativeStateFiles::open(&state).is_ok());
    Ok(())
}
#[test]
fn negative_proof_and_replaced_directory() -> Result {
    let root = std::env::temp_dir().join(format!("se-negative-proof-{}", std::process::id()));
    assert!(!root.exists(), "preserve an existing fixture");
    fs::create_dir(&root)?;
    let _root_owner = cleanup_directory::PrivateDirectory::adopt(root.clone());
    mode(&root, 0o700)?;
    fs::write(root.join("control"), b"0")?;
    let library = root.join("negative-account.so");
    let build = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&library)
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/ancestor_negative_account.c"),
        )
        .arg("-ldl")
        .output()?;
    assert!(
        build.status.success(),
        "native fixture compilation: {build:?}"
    );
    let output = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "negative_proof_child"])
        .env("SE_NEGATIVE_PROOF_ROOT", &root)
        .env("SE_ANCESTOR_NSS_CONTROL", root.join("control"))
        .env("LD_PRELOAD", &library)
        .output()?;
    assert!(output.status.success(), "native boundary child: {output:?}");
    for name in ["ancestor", "retired"] {
        fs::remove_dir(root.join(name).join("state"))?;
        fs::remove_dir(root.join(name))?;
    }
    fs::remove_file(root.join("control"))?;
    fs::remove_file(library)?;
    fs::remove_dir(root)?;
    Ok(())
}
