//! The optional private hook cannot create a host or wait forever on stdin.
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[test]
fn missing_host_and_unclosed_provider_input_are_silent_and_finite()
-> Result<(), Box<dyn std::error::Error>> {
    se_proc::initialize_file_creation_owner()?;
    let home = std::env::temp_dir().join(format!(
        "se-atlas-hook-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let files = se_proc::NativeStateFiles::create(&home)?;
    fs::write(
        home.join("config.toml"),
        "[atlas]\nenabled = true\nhooks = true\n",
    )?;
    let session = se_types::SessionId::from_parts(1, [67; 10])?;
    let token = se_types::Secret::new(
        format!("sec1.{}.{}", session.as_str(), "A".repeat(43)).into_bytes(),
    )?;
    se_proc::publish_session_pin(&files, &session, &token)?;
    let image = PathBuf::from(env!("CARGO_BIN_EXE_se")).canonicalize()?;
    let mut command = Command::new(&image);
    command
        .arg("--stateengine-private-atlas-hook")
        .arg(&home)
        .env("SE_SESSION", session.as_str())
        .env_remove("SE_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let mut input = child.stdin.take().ok_or("provider stdin absent")?;
    input.write_all(
        br#"{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"alpha"}}"#,
    )?;
    drop(input);
    let result = child.wait_with_output()?;
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
    assert!(!home.join("endpoint.json").exists());
    assert!(!home.join("runtime.lock").exists());
    assert!(!home.join("store.db").exists());
    let mut child = command.spawn()?;
    let held = child.stdin.take().ok_or("second provider stdin absent")?;
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(status.success());
            break;
        }
        if Instant::now() >= end {
            child.kill()?;
            child.wait()?;
            return Err("private hook waited for an unclosed provider stdin".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(held);
    drop(files);
    // Only this test's newly created data home is removed, after native handles close.
    fs::remove_dir_all(&home)?;
    Ok(())
}
