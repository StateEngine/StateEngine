//! Provider-owned scratch must stay independent of launch cleanup authority.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

fn judge(script: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parent = directory::private_directory()?;
    let root = parent.join("output");
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/judges")
                .join(script),
        )
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "retained provider scratch fixture {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(parent)?;
    Ok(())
}

/// Protects: nested provider files and unrelated link targets survive warm and cold stop/down.
#[test]
fn provider_temporary_files_do_not_block_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    judge("provider_temporary.py")
}

/// Protects: even an unused scratch directory cannot become unmanifested launch metadata.
#[test]
fn unused_provider_scratch_does_not_block_cold_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    judge("empty_scratch_cleanup.py")
}
