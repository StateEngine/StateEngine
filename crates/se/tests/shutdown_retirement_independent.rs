//! Eight native provider scopes must close together without losing final capture.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;
/// Protects: complete multi-agent shutdown retains exact final conversations and closes original native births, recovery metadata, endpoint and lease.
/// Bug: simultaneous terminal metadata removals contended on the shared native directory lock and left shutdown incomplete.
#[test]
fn sibling_native_shutdown_preserves_final_capture_and_closes_every_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = directory::private_directory()?;
    let root = parent.join("output");
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/shutdown_retirement.py"
        ))
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "retained {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(parent)?;
    Ok(())
}
