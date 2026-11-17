//! Saved overrides must reach the owned provider on fresh and resumed launches.
//! Protocol doubles exercise the public CLI/MCP consumers without model accounts.
#![cfg(target_os = "linux")]
use std::{path::PathBuf, process::Command};

#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn saved_provider_overrides_reach_both_launch_consumers() -> Result<(), Box<dyn std::error::Error>>
{
    let home = directory::private_case_directory()?;
    let root = home.join("consumer");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/judges/provider_settings_consumer_review.py");
    let output = Command::new("python3")
        .arg(script)
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .output()?;
    let diagnostics = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/provider-settings-consumer");
    std::fs::create_dir_all(&diagnostics)?;
    std::fs::write(diagnostics.join("stdout.txt"), &output.stdout)?;
    std::fs::write(diagnostics.join("stderr.txt"), &output.stderr)?;
    if root.join("result.json").exists() {
        std::fs::copy(root.join("result.json"), diagnostics.join("result.json"))?;
    }
    assert!(
        output.status.success(),
        "consumer failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    home.finish(Ok(()))
}
