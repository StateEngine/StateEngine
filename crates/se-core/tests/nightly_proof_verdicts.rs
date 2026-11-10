//! Independent retained-receipt controls for the Linux scheduler adapter.
#[cfg(target_os = "linux")]
#[test]
fn nightly_receipts_separate_behavior_budgets_and_interruption()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("workspace root absent")?;
    let output = std::process::Command::new("python3")
        .arg(manifest.join("tests/support/nightly_verdicts.py"))
        .arg("--source")
        .arg(root.join("factory/proof"))
        .output()?;
    assert!(
        output.status.success(),
        "Python controls failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
