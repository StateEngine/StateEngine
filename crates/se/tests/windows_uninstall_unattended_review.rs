//! Public unattended removal must finish without a console or lost user files.
#![cfg(windows)]

#[path = "support/installation_account.rs"]
mod installation_account;

#[test]
fn public_uninstall_yes_finishes_with_redirected_standard_handles()
-> Result<(), Box<dyn std::error::Error>> {
    installation_account::require()?;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = root
        .join("target/judge-diagnostics/unattended-uninstall")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&output)?;
    let result = std::process::Command::new("python")
        .arg("-I")
        .arg(root.join("crates/se/tests/windows_uninstall_unattended_review.py"))
        .arg("--image")
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg("--repository")
        .arg(&root)
        .arg("--out")
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "public unattended uninstall failed; receipts at {}\nstdout={}\nstderr={}",
        output.display(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
