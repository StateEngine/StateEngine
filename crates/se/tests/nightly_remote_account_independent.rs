//! Native account selection must precede remote staging and credential handoff.
#![cfg(target_os = "linux")]

#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn remote_account_selection_refuses_before_staging_and_reports_red()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("workspace root missing")?;
    let artifacts = root.join("target/judge-diagnostics/remote-account-guard");
    std::fs::create_dir_all(&artifacts)?;
    let fixture = directory::private_directory()?;
    let output = std::process::Command::new("python3")
        .arg("-B")
        .arg(root.join("crates/se/tests/support/nightly_remote_account.py"))
        .arg(root)
        .arg(fixture.as_ref())
        .arg(&artifacts)
        .output()?;
    assert!(
        output.status.success(),
        "independent account guard controls failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
