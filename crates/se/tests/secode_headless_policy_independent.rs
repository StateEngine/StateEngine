//! Public launch admission and native refusal cleanup; no account or model turn.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

type Check = Result<(), Box<dyn std::error::Error>>;

fn require_link_free(path: &std::path::Path) -> Check {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(format!("retained fixture link: {}", path.display()).into());
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            require_link_free(&entry?.path())?;
        }
    }
    Ok(())
}

/// Protects: saved workspace authority is not widened, unsupported providers
/// refuse before input, and missing workspaces refuse before auxiliary startup.
#[test]
fn saved_policy_and_refused_preparation_preserve_native_custody() -> Check {
    let root = directory::private_directory()?;
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_se"));
    let image = if source.metadata()?.len() > 512 * 1024 * 1024 {
        // Remove debug symbols from an owned copy, never the build image or
        // the native regular-image proof bound used by the running host.
        let image = root.join("se");
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
            "/tests/judges/secode_headless_policy.py"
        ))
        .arg("--se")
        .arg(image)
        .arg("--capabilities")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/secode_headless_capabilities.json"
        ))
        .arg("--output")
        .arg(root.join("output"))
        .output()?;
    assert!(
        output.status.success(),
        "retained headless fixture {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Success includes public down and outside process/endpoint readback for
    // every fixture. Failure preserves its root for diagnosis, never a false pass.
    require_link_free(&root)?;
    Ok(())
}
