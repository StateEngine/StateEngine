//! Judge actual nested launch environments and saved conversation selection.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

fn judge(case: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parent = directory::private_directory()?;
    let root = parent.join("output");
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_se"));
    let image = if source.metadata()?.len() > 512 * 1024 * 1024 {
        // Match the native regular-image proof bound without changing the build.
        let image = parent.join("se");
        std::fs::copy(source, &image)?;
        let stripped = std::process::Command::new("strip")
            .arg("--strip-debug")
            .arg(&image)
            .output()?;
        assert!(
            stripped.status.success(),
            "owned debug image preparation failed: {}",
            String::from_utf8_lossy(&stripped.stderr)
        );
        image
    } else {
        source.to_path_buf()
    };
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/launch_continuity.py"
        ))
        .arg("--se")
        .arg(image)
        .args(["--case", case, "--output"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "retained launch continuity fixture {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(parent)?;
    Ok(())
}

/// Protects: a parent-created CLI/MCP child gets only its own session identity.
#[test]
fn nested_launch_discards_parent_provider_and_identity_markers()
-> Result<(), Box<dyn std::error::Error>> {
    judge("nested")
}

/// Protects: an ordinary launch visibly resumes with age; --new really starts fresh.
#[test]
fn saved_conversation_launch_explains_resume_and_age_and_new_starts_fresh()
-> Result<(), Box<dyn std::error::Error>> {
    judge("resume")
}
