//! Public direct/hosted CLI consumers; the protocol uses no model account.
#![cfg(any(target_os = "linux", windows))]
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn direct_and_hosted_rename_preserve_identity_and_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let root = directory::private_directory()?;
    let python = if cfg!(windows) { "python" } else { "python3" };
    let output = std::process::Command::new(python)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/agent_rename.py"
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
