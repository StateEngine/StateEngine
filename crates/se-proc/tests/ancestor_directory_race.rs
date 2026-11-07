//! Real native traversal retries an incomplete account proof, never unsafe ownership.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use se_proc::{NativeStateFiles, StateFileErrorCode};
use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
#[path = "../../test-support/directory.rs"]
mod directory;
type Check = Result<(), Box<dyn Error>>;
#[test]
#[ignore = "native NSS race child invoked by concurrent_directory_entries_reprove_authority"]
fn account_race_child() -> Check {
    let parent = std::env::var_os("SE_ANCESTOR_RACE_PARENT").ok_or("race parent absent")?;
    let parent = Path::new(&parent);
    fs::create_dir(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let state = parent.join("state");
    drop(NativeStateFiles::create(&state)?);
    fs::set_permissions(parent, fs::Permissions::from_mode(0o775))?;
    let result = NativeStateFiles::open(&state);
    let mode = std::env::var("SE_ANCESTOR_RACE_MODE")?;
    match mode.as_str() {
        "once" => {
            let files = result?;
            assert!(files.readback(&state.join("absent"))?.is_none());
        }
        "continuous" => {
            assert_eq!(
                result.err().ok_or("continuous drift accepted")?.code,
                StateFileErrorCode::SourceChanged
            );
            assert!(parent.join("sibling-2").exists());
            assert!(!parent.join("sibling-3").exists());
        }
        "unsafe" => {
            assert_eq!(
                result.err().ok_or("changed permissions accepted")?.code,
                StateFileErrorCode::LocationUnsafe
            );
            fs::set_permissions(parent, fs::Permissions::from_mode(0o775))?;
        }
        _ => return Err("unknown mode".into()),
    }
    Ok(())
}
#[test]
fn concurrent_directory_entries_reprove_authority() -> Check {
    let root = directory::private_directory()?;
    let library = root.join("race.so");
    fs::write(root.join("control"), b"0")?;
    let built = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&library)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/ancestor_directory_race.c"))
        .arg("-ldl")
        .output()?;
    assert!(built.status.success(), "NSS fixture build: {built:?}");
    for mode in ["once", "continuous", "unsafe"] {
        let output = Command::new(std::env::current_exe()?)
            .args(["--ignored", "--exact", "account_race_child"])
            .env("SE_ANCESTOR_RACE_PARENT", root.join(mode))
            .env("SE_ANCESTOR_RACE_MODE", mode)
            .env("SE_ANCESTOR_NSS_CONTROL", root.join("control"))
            .env("LD_PRELOAD", &library)
            .output()?;
        assert!(output.status.success(), "{mode}: {output:?}");
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
