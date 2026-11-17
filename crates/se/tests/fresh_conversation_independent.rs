//! Real native provider and authenticated CLI/MCP consumers of launch selection.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn fresh_and_explicit_resume_preserve_context_across_cli_and_mcp()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = directory::private_directory()?;
    let output = parent.join("output");
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_se"));
    let image = parent.join("se");
    std::fs::copy(source, &image)?;
    let stripped = std::process::Command::new("strip")
        .arg("--strip-debug")
        .arg(&image)
        .output()?;
    assert!(
        stripped.status.success(),
        "owned fixture image preparation failed"
    );
    let run = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/fresh_conversation.py"
        ))
        .arg("--se")
        .arg(image)
        .arg("--output")
        .arg(&output)
        .output()?;
    assert!(
        run.status.success(),
        "fixture {}: {} {}",
        output.display(),
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    Ok(())
}
