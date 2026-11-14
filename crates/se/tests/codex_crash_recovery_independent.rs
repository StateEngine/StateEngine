//! Public CLI recovery controls with a persistent native protocol double.
//! No provider account, real conversation turn or paid request is exercised.
#![cfg(target_os = "linux")]
use std::{path::PathBuf, process::Command};
#[path = "../../test-support/directory.rs"]
mod directory;

fn judge(scenario: &str) -> Result<(), Box<dyn std::error::Error>> {
    let home = directory::private_case_directory()?;
    let root = home.join("run");
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/judges/codex_recovery_cli.py");
    let output = Command::new("python3")
        .arg(script)
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .args(["--scenario", scenario])
        .output()?;
    let diagnostics = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics")
        .join(format!("provider-recovery-{scenario}"));
    std::fs::create_dir_all(&diagnostics)?;
    std::fs::write(diagnostics.join("stdout.txt"), &output.stdout)?;
    std::fs::write(diagnostics.join("stderr.txt"), &output.stderr)?;
    if root.join("result.json").exists() {
        std::fs::copy(root.join("result.json"), diagnostics.join("result.json"))?;
    }
    assert!(
        output.status.success(),
        "public CLI {scenario} recovery failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    home.finish(Ok(()))
}

#[test]
fn runtime_crash_preserves_orphan_until_explicit_forced_relaunch()
-> Result<(), Box<dyn std::error::Error>> {
    judge("crash")
}

#[test]
fn runtime_crash_never_reaps_a_slow_live_provider() -> Result<(), Box<dyn std::error::Error>> {
    judge("slow")
}
