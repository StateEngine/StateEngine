//! Preview a fresh native Windows store through the public assignment commands.
#![cfg(windows)]

#[test]
fn fresh_windows_store_supports_assignment_history() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = root.join("../../target/judge-diagnostics/assignment-migration-review");
    let result = std::process::Command::new("python")
        .args(["-I", "-B"])
        .arg(root.join("tests/judges/assignment_migration_review.py"))
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
