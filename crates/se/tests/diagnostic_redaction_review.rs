//! Reviewer-owned public CLI checks for secrets inside structured diagnostic text.
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn structured_diagnostic_text_never_exports_credential_canaries()
-> Result<(), Box<dyn std::error::Error>> {
    se_proc::initialize_file_creation_owner()?;
    let root = directory::private_directory()?;
    let output = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/diagnostic_redaction_review.py"
        ))
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(root.to_path_buf())
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
