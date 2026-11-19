//! Independent Win32 watcher controls through the normal status command.
#![cfg(windows)]

#[test]
fn windows_watcher_freshness_and_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = root.join("../../target/judge-diagnostics/windows-watch-review");
    let result = std::process::Command::new("python")
        .args(["-I", "-B"])
        .arg(root.join("tests/judges/windows_watch_review.py"))
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg(output)
        .output()?;
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
