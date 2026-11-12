//! Completed replies and verified capture survive an uncertain native hook write.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

type Check = Result<(), Box<dyn std::error::Error>>;

fn judge(arguments: &[&str]) -> Check {
    let parent = directory::private_directory()?;
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_se"));
    let image = if source.metadata()?.len() > 512 * 1024 * 1024 {
        // The regular-image proof bound also applies to local debug builds.
        // Remove only debug symbols from an owned copy, never the build image.
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
            "/tests/judges/claude_first_hour_capture.py"
        ))
        .arg("--se")
        .arg(image)
        .arg("--output")
        .arg(parent.join("output"))
        .args(arguments)
        .output()?;
    assert!(
        output.status.success(),
        "retained capture fixture {}: {} {}",
        parent.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn unimpeded_capture_keeps_one_original_reply() -> Check {
    judge(&["--no-delay-commit"])
}

#[test]
fn delayed_metadata_commit_continues_to_the_pinned_reply() -> Check {
    judge(&["--delay-record", "metadata"])
}

#[test]
fn delayed_final_reply_commit_clears_failure_before_resume() -> Check {
    judge(&["--delay-record", "reply"])
}
