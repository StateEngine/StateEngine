//! A real failed native stop can be retried, including through host shutdown.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn stop_unproved_retries_use_the_current_durable_transition()
-> Result<(), Box<dyn std::error::Error>> {
    let root = directory::private_directory()?;
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/stop_retry_transition.py"
        ))
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(root.join("output"))
        .output()?;
    assert!(
        output.status.success(),
        "retained {}: {}{}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
