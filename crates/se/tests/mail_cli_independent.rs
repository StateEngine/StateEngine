//! Real CLI/MCP mail budgets, recipient dispositions and witnessed shutdown.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn mail_reads_respect_budgets_and_share_recipient_receipts()
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
            "/tests/judges/mail_cli.py"
        ))
        .arg("--se")
        .arg(image)
        .arg("--output")
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "retained mail fixture {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(parent)?;
    Ok(())
}
