//! Native in-scope MCP self-force and fresh-successor replay.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn self_force_joins_old_scope_and_fresh_admission_replay_preserves_one_successor()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = directory::private_directory()?;
    let root = parent.join("output");
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_se"));
    let image = if source.metadata()?.len() > 512 * 1024 * 1024 {
        let image = parent.join("se");
        std::fs::copy(source, &image)?;
        let stripped = std::process::Command::new("strip")
            .arg("--strip-debug")
            .arg(&image)
            .output()?;
        assert!(
            stripped.status.success(),
            "owned debug image preparation failed"
        );
        image
    } else {
        source.to_path_buf()
    };
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/force_self_independent.py"
        ))
        .arg("--se")
        .arg(image)
        .arg("--output")
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "retained self-force fixture {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
