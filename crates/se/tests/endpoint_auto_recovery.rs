//! Real CLI recovery must retain protected routing records without probing a foreign address.
#![cfg(target_os = "linux")]
#![allow(dead_code, reason = "Shared native fixture serves other consumers.")]
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "support/runtime_host.rs"]
mod runtime_host;
use fixture::*;
use sha2::Digest;
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Output},
};
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
        "XDG_RUNTIME_DIR",
    ] {
        command.env_remove(name);
    }
    command
}
fn checked(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "CLI failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn publish(files: &se_proc::NativeStateFiles, bytes: &[u8]) -> Check {
    let mut staged = files.create_staging(files.root())?;
    staged.file.write_all(bytes)?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &files.root().join("endpoint.json"))?;
    Ok(())
}
fn retained(home: &Path) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(home)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("endpoint.retained-")
        {
            names.push(entry.path());
        }
    }
    names.sort();
    Ok(names)
}
fn untouched_foreign(
    listener: &se_proc::native_ipc::NativeUnixEndpoint,
    path: &Path,
    original: &fs::Metadata,
) -> Check {
    let actual = fs::symlink_metadata(path)?;
    assert_eq!(
        (actual.dev(), actual.ino(), actual.uid(), actual.mode()),
        (
            original.dev(),
            original.ino(),
            original.uid(),
            original.mode()
        )
    );
    match listener.listener().accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Ok(_) => Err("recovery or busy refusal connected to the mismatched address".into()),
        Err(error) => Err(error.into()),
    }
}

/// Protects: automatic CLI recovery reports the exact retained file in JSON/human output, preserves its native identity, never probes a mismatched address, and cannot mutate records under a live lease or bypass unsafe permissions.
#[test]
fn automatic_retention_is_visible_and_live_or_unsafe_records_are_preserved() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let image = f.home.join("auto-recovery-se");
    fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let repository = f.home.join("repository");
    fs::create_dir(&repository)?;
    checked(
        command(&image, home, true)
            .arg("init")
            .arg("--repo")
            .arg(repository)
            .output()?,
    )?;
    let first = runtime_host::RunningHost::start(&image, home)?;
    let mut stale =
        se_host::client::endpoint::decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
    first.stop()?;
    let foreign_directory = f.home.join("foreign");
    drop(se_proc::NativeStateFiles::create(&foreign_directory)?);
    let foreign_path = foreign_directory.join("foreign.sock");
    let foreign = se_proc::native_ipc::NativeUnixEndpoint::bind(&foreign_path)?;
    foreign.listener().set_nonblocking(true)?;
    let foreign_metadata = fs::symlink_metadata(&foreign_path)?;
    stale.address =
        se_host::IpcEndpoint::UnixSocket(se_types::NativePath::from_local(foreign_path.clone())?);
    let bytes = se_host::client::endpoint::encode_endpoint(&stale)?;
    let files = se_proc::NativeStateFiles::open(home)?;
    // Down must retire obsolete routing records too, without touching even a
    // live foreign socket named by the stale record. Both renderers expose it.
    for json in [true, false] {
        publish(&files, bytes.as_bytes())?;
        let before = retained(home)?;
        let output = command(&image, home, json).arg("down").output()?;
        assert!(
            output.status.success(),
            "stale down refused: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!home.join("endpoint.json").exists());
        let after = retained(home)?;
        let added: Vec<_> = after.iter().filter(|path| !before.contains(path)).collect();
        assert_eq!(added.len(), 1);
        assert_eq!(fs::read(added[0])?, bytes.as_bytes());
        let printed = String::from_utf8(output.stdout)?;
        assert!(
            printed.contains("Retained stale endpoint")
                && printed.contains(&added[0].display().to_string())
        );
        if json {
            let stop: se_core::ops::RuntimeStop = serde_json::from_str(&printed)?;
            assert!(stop.complete && stop.already_down);
            assert!(stop.stops.is_empty());
        }
        untouched_foreign(&foreign, &foreign_path, &foreign_metadata)?;
    }
    let machine = fs::read(home.join("machine.json"))?;
    let credential = fs::read(home.join("credential"))?;
    for json in [true, false] {
        publish(&files, bytes.as_bytes())?;
        let old = fs::symlink_metadata(home.join("endpoint.json"))?;
        let before = retained(home)?;
        let output = command(&image, home, json).arg("up").output()?;
        assert!(
            output.status.success(),
            "automatic recovery refused: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let host = runtime_host::RunningHost::start(&image, home)?;
        let after = retained(home)?;
        let added: Vec<_> = after.iter().filter(|path| !before.contains(path)).collect();
        assert_eq!(added.len(), 1, "recovery must retain one exact record");
        let saved = added[0];
        assert_eq!(fs::read(saved)?, bytes.as_bytes());
        let metadata = fs::symlink_metadata(saved)?;
        assert_eq!(
            (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.mode()
            ),
            (old.dev(), old.ino(), old.uid(), old.mode())
        );
        if json {
            let start: se_core::ops::RuntimeStart = serde_json::from_slice(&output.stdout)?;
            let recovery = start
                .endpoint_recovery
                .ok_or("JSON omitted achieved endpoint retention")?;
            assert_eq!(recovery.original.to_local()?, home.join("endpoint.json"));
            assert_eq!(&recovery.retained.to_local()?, saved);
        } else {
            let printed = String::from_utf8(output.stdout)?;
            assert!(
                printed.contains("Retained stale endpoint")
                    && printed.contains(&home.join("endpoint.json").display().to_string())
                    && printed.contains(&saved.display().to_string()),
                "human output omitted achieved retention: {printed}"
            );
        }
        untouched_foreign(&foreign, &foreign_path, &foreign_metadata)?;
        assert_eq!(fs::read(home.join("machine.json"))?, machine);
        assert_eq!(fs::read(home.join("credential"))?, credential);
        assert!(host.live()?);
        let endpoint = home.join("endpoint.json");
        let backup = home.join("live-endpoint.fixture");
        fs::rename(&endpoint, &backup)?;
        publish(&files, bytes.as_bytes())?;
        for mode in [true, false] {
            let refusal = command(&image, home, mode).arg("up").output()?;
            assert!(
                !refusal.status.success(),
                "busy lease allowed endpoint recovery"
            );
            let printed = format!(
                "{}{}",
                String::from_utf8_lossy(&refusal.stdout),
                String::from_utf8_lossy(&refusal.stderr)
            );
            assert!(
                printed.contains("se down"),
                "busy refusal lacks legal recovery: {printed}"
            );
            assert_eq!(fs::read(&endpoint)?, bytes.as_bytes());
            assert_eq!(retained(home)?, after);
            assert!(host.live()?);
            untouched_foreign(&foreign, &foreign_path, &foreign_metadata)?;
        }
        se_proc::OwnedFile::open(&endpoint)?
            .ok_or("busy test record disappeared")?
            .remove(sha2::Sha256::digest(bytes.as_bytes()).into())?;
        fs::rename(backup, &endpoint)?;
        host.stop()?;
        assert!(!endpoint.try_exists()?);
    }
    publish(&files, bytes.as_bytes())?;
    let endpoint = home.join("endpoint.json");
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o644))?;
    let before = retained(home)?;
    for json in [true, false] {
        let output = command(&image, home, json).arg("up").output()?;
        assert!(!output.status.success(), "unsafe record was recovered");
        assert_eq!(fs::read(&endpoint)?, bytes.as_bytes());
        assert_eq!(fs::symlink_metadata(&endpoint)?.mode() & 0o777, 0o644);
        assert_eq!(retained(home)?, before);
        untouched_foreign(&foreign, &foreign_path, &foreign_metadata)?;
    }
    fs::set_permissions(endpoint, fs::Permissions::from_mode(0o600))?;
    assert_eq!(fs::read(home.join("machine.json"))?, machine);
    assert_eq!(fs::read(home.join("credential"))?, credential);
    foreign.close()?;
    Ok(())
}

/// Protects: empty persisted endpoint bytes are an unreadable runtime fault in
/// both renderers; a live lease never supplies permission to retain the file.
#[test]
fn empty_live_endpoint_is_diagnosed_and_send_keeps_the_same_cause() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let image = f.home.join("empty-endpoint-se");
    fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let repository = f.home.join("repository");
    fs::create_dir(&repository)?;
    let initialized = checked(
        command(&image, home, true)
            .arg("init")
            .arg("--repo")
            .arg(&repository)
            .arg("--agent")
            .arg("Worker")
            .arg("--provider")
            .arg("claude")
            .output()?,
    )?;
    let agent = initialized["agent"]["id"]
        .as_str()
        .ok_or("init omitted agent")?;
    let project = initialized["project"]["id"]
        .as_str()
        .ok_or("init omitted project")?;
    let host = runtime_host::RunningHost::start(&image, home)?;
    let endpoint = home.join("endpoint.json");
    let before = fs::metadata(&endpoint)?;
    fs::write(&endpoint, [])?;
    // RunningHost retains authenticated routing for exact graceful cleanup,
    // without restoring the corrupt record or trusting its existence.
    for json in [true, false] {
        let diagnosis = command(&image, home, json).arg("doctor").output()?;
        assert!(!diagnosis.status.success());
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&diagnosis.stdout),
            String::from_utf8_lossy(&diagnosis.stderr)
        );
        assert!(
            printed.contains("empty") && printed.contains("zero bytes"),
            "{printed}"
        );
        assert!(!printed.contains("live routing is preserved"), "{printed}");
        if json {
            let value: serde_json::Value = serde_json::from_slice(&diagnosis.stdout)?;
            let row = value["checks"]
                .as_array()
                .ok_or("checks omitted")?
                .iter()
                .find(|row| row["id"] == "runtime.endpoint")
                .ok_or("endpoint check omitted")?;
            assert_eq!(row["state"], "failed");
            assert_eq!(row["code"], "source-unreadable");
            assert_eq!(row["repairable"], false);
        }
        let send = command(&image, home, json)
            .arg("--project")
            .arg(project)
            .args([
                "msg",
                "send",
                agent,
                "empty endpoint fault",
                "--key",
                "empty-endpoint-fault",
            ])
            .output()?;
        assert!(!send.status.success());
        assert_ne!(
            send.status.code(),
            Some(64),
            "runtime state was presented as caller misuse"
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&send.stdout),
            String::from_utf8_lossy(&send.stderr)
        );
        assert!(
            text.contains("empty") && text.contains("runtime.endpoint"),
            "{text}"
        );
        assert_eq!(fs::read(&endpoint)?, Vec::<u8>::new());
        let after = fs::metadata(&endpoint)?;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert!(host.live()?);
    }
    host.stop()?;
    Ok(())
}
