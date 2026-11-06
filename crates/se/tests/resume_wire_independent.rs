//! Resume must fit its complete MCP framing while retaining useful context.
#![cfg(target_os = "linux")]
/// Protects: the default four-KiB resume is usable through real authenticated
/// stdio and HTTP, with honest omissions, runnable recovery and unchanged mail.
#[test]
fn default_resume_fits_complete_wire_and_preserves_read_obligations()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "se-resume-wire-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/resume_wire.py"
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
    std::fs::remove_dir_all(root)?;
    Ok(())
}
