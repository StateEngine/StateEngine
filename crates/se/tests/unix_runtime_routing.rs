//! The busy-home comparison must use the same explicit XDG selector as bind.
#![cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
#[path = "support/runtime_host.rs"]
mod runtime_host;

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
    // This fixture's explicit platform root is also passed to every repeated
    // CLI call made by the shared exact-instance cleanup helper.
    command.env("XDG_RUNTIME_DIR", home.with_file_name("x"));
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
#[test]
fn repeated_up_for_a_long_home_keeps_the_same_xdg_host_and_native_socket() -> Check {
    let root = PathBuf::from("/tmp").join(format!(
        "se-route-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let runtime = root.join("x");
    fs::create_dir(&runtime)?;
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
    let repository = root.join("repository");
    fs::create_dir(&repository)?;
    let home = root.join("long-state-home-".repeat(8));
    let image = root.join("se");
    fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    checked(
        command(&image, &home, true)
            .arg("init")
            .arg("--repo")
            .arg(&repository)
            .output_executable()?,
    )?;
    let host = runtime_host::RunningHost::start(&image, &home)?;
    let record = fs::read(home.join("endpoint.json"))?;
    let endpoint = se_host::client::endpoint::decode_endpoint(&record)?;
    let se_host::IpcEndpoint::UnixSocket(path) = endpoint.address else {
        return Err("not a Unix endpoint".into());
    };
    let socket = path.to_local()?;
    assert!(socket.starts_with(runtime.join("stateengine")));
    assert!(
        home.join("runtime.sock")
            .as_os_str()
            .as_encoded_bytes()
            .len()
            > 108
    );
    let metadata = fs::symlink_metadata(&socket)?;
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    let parent = fs::metadata(socket.parent().ok_or("socket parent")?)?;
    assert_eq!(parent.mode() & 0o7777, 0o700);
    assert_eq!(metadata.uid(), fs::metadata(&home)?.uid());
    assert_eq!(parent.uid(), metadata.uid());
    let machine = fs::read(home.join("machine.json"))?;
    let credential = fs::read(home.join("credential"))?;
    checked(command(&image, &home, true).arg("up").output_executable()?)?;
    assert!(host.live()?);
    assert_eq!(fs::read(home.join("endpoint.json"))?, record);
    assert_eq!(fs::read(home.join("machine.json"))?, machine);
    assert_eq!(fs::read(home.join("credential"))?, credential);
    let after = fs::symlink_metadata(&socket)?;
    assert_eq!(
        (after.dev(), after.ino(), after.uid(), after.mode()),
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.mode()
        )
    );
    host.stop()?;
    assert!(!host.live()?);
    assert!(!socket.try_exists()?);
    assert!(!home.join("endpoint.json").try_exists()?);
    let lock = fs::File::open(home.join("runtime.lock"))?;
    lock.try_lock()?;
    drop(lock);
    drop(host);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
