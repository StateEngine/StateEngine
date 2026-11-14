//! Fresh native setup timing; this diagnostic does not certify another machine's I/O.
#![cfg(target_os = "linux")]
use std::{path::PathBuf, process::Command};

#[test]
fn fresh_ordinary_init_retains_deadline_and_phase_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python3")
        .arg("-B")
        .arg(root.join("tests/judges/init_latency_diagnostic.py"))
        .arg("--se")
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg("--output")
        .arg(root.join("../../target/judge-diagnostics/init-latency"))
        .output()?;
    assert!(
        output.status.success(),
        "fresh init diagnostic refused or crossed its original observation ceiling: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
