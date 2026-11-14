//! Actual native custody failures must not invent a filesystem diagnosis.
#![cfg(unix)]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
fn command(image: &Path, home: &Path, json: bool) -> Command {
    let mut command = Command::new(image);
    if json {
        command.arg("--json");
    }
    command.arg("--home").arg(home);
    for name in [
        "SE_HOME",
        "SE_PROJECT",
        "SE_CONFIG",
        "SE_LOG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    command
}

/// Protects: JSON and human init/status report a real unsafe home with its native cause and ownership/protection recovery, preserve its bytes and mode, and accept the same directory after protection is restored.
#[test]
fn unsafe_home_reports_native_custody_and_preserves_existing_state() -> Check {
    let root = std::env::temp_dir().join(format!(
        "se-test-install-home-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    let _root_owner = cleanup_directory::PrivateDirectory::adopt(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let image = root.join("se");
    fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let home = root.join("state");
    fs::create_dir(&home)?;
    let sentinel = home.join("existing-state");
    fs::write(&sentinel, b"retain original state")?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o777))?;
    let before = fs::symlink_metadata(&home)?;
    for operation in ["init", "status"] {
        for json in [true, false] {
            let output = command(&image, &home, json)
                .arg(operation)
                .output_executable()?;
            assert!(!output.status.success(), "unsafe home was accepted");
            let printed = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                printed.contains("LocationUnsafe")
                    && printed.contains(&home.display().to_string())
                    && printed.contains("restore native ownership/protection"),
                "actual custody cause or legal recovery was lost: {printed}"
            );
            assert!(
                !printed.contains("local disk") && !printed.contains("home-unsupported-location"),
                "custody failure invented a disk diagnosis: {printed}"
            );
            if json {
                let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(value["code"], "state-conflict");
            } else {
                assert!(output.stdout.is_empty());
            }
            let after = fs::symlink_metadata(&home)?;
            assert_eq!(
                (after.dev(), after.ino(), after.uid(), after.mode()),
                (before.dev(), before.ino(), before.uid(), before.mode())
            );
            assert_eq!(fs::read(&sentinel)?, b"retain original state");
            assert_eq!(fs::read_dir(&home)?.count(), 1);
        }
    }
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
    let output = command(&image, &home, true)
        .arg("status")
        .output_executable()?;
    assert!(
        output.status.success(),
        "private empty home status refused: {output:?}"
    );
    assert_eq!(fs::read(&sentinel)?, b"retain original state");
    assert_eq!(fs::read_dir(&home)?.count(), 1);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
