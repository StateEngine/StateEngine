//! Public CLI recovery controls with a persistent native protocol double.
//! No provider account, real conversation turn or paid request is exercised.
#![cfg(target_os = "linux")]
use std::{path::PathBuf, process::Command};

fn judge(scenario: &str) {
    let root = std::env::temp_dir().join(format!(
        "provider-recovery-{}-{scenario}",
        std::process::id()
    ));
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/judges/codex_recovery_cli.py");
    let output = Command::new("python3")
        .arg(script)
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .args(["--scenario", scenario])
        .output()
        .expect("start the independent public CLI recovery control");
    let diagnostics = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics")
        .join(format!("provider-recovery-{scenario}"));
    std::fs::create_dir_all(&diagnostics).expect("create diagnostic directory");
    std::fs::write(diagnostics.join("stdout.txt"), &output.stdout).expect("retain driver stdout");
    std::fs::write(diagnostics.join("stderr.txt"), &output.stderr).expect("retain driver stderr");
    if root.join("result.json").exists() {
        std::fs::copy(root.join("result.json"), diagnostics.join("result.json"))
            .expect("retain outside process observations");
    }
    assert!(
        output.status.success(),
        "public CLI {scenario} recovery failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn runtime_crash_preserves_orphan_until_explicit_forced_relaunch() {
    judge("crash");
}

#[test]
fn runtime_crash_never_reaps_a_slow_live_provider() {
    judge("slow");
}
