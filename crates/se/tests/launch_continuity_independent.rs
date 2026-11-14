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

// Development repetitions retain the original control and its per-case timeout.
macro_rules! repeat_saved_conversation {
    ($($name:ident),+ $(,)?) => {$(
        #[test]
        fn $name() -> Result<(), Box<dyn std::error::Error>> {
            judge("resume")
        }
    )+};
}
repeat_saved_conversation!(
    repeat_saved_conversation_01,
    repeat_saved_conversation_02,
    repeat_saved_conversation_03,
    repeat_saved_conversation_04,
    repeat_saved_conversation_05,
    repeat_saved_conversation_06,
    repeat_saved_conversation_07,
    repeat_saved_conversation_08,
    repeat_saved_conversation_09,
    repeat_saved_conversation_10,
    repeat_saved_conversation_11,
    repeat_saved_conversation_12,
    repeat_saved_conversation_13,
    repeat_saved_conversation_14,
    repeat_saved_conversation_15,
    repeat_saved_conversation_16,
    repeat_saved_conversation_17,
    repeat_saved_conversation_18,
    repeat_saved_conversation_19,
    repeat_saved_conversation_20,
);
