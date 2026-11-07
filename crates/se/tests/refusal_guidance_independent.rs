//! Refusal advice must lead to a working public CLI command at the same scope.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;
/// Protects: refusal advice leads to real CLI recovery in the same home/project without changing stop scope or existing files.
#[test]
fn refusal_advice_and_recovery_work_in_plain_and_json_output()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = directory::private_directory()?;
    let root = parent.join("output");
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/refusal_guidance.py"
        ))
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "retained refusal fixture {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(parent)?;
    Ok(())
}
