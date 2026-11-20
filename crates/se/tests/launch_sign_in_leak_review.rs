//! A terminal's provider sign-in must serve only the launch that carried it.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

/// Protects: the token reaches one launch's child, the next launch without it is
/// refused as signed out, and no file, output or host environment retains it.
#[test]
fn terminal_sign_in_serves_one_launch_and_leaves_no_trace() -> Result<(), Box<dyn std::error::Error>>
{
    let parent = directory::private_directory()?;
    let root = parent.join("output");
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/judges/launch_sign_in_leak.py"),
        )
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "launch sign-in fixture {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
