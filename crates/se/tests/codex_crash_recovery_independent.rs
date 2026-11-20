//! Public CLI recovery controls with a persistent native protocol double.
//! No provider account, real conversation turn or paid request is exercised.
#![cfg(any(target_os = "linux", windows))]
use std::{path::PathBuf, process::Command};
#[path = "../../test-support/directory.rs"]
mod directory;

fn judge(scenario: &str) -> Result<(), Box<dyn std::error::Error>> {
    let home = directory::private_case_directory()?;
    let root = home.join("run");
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/judges/codex_recovery_cli.py");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_se"));
    let binary = if cfg!(windows) {
        let owned = home.join("se.exe");
        std::fs::copy(&binary, &owned)?;
        owned
    } else {
        binary
    };
    let python = if cfg!(windows) { "python" } else { "python3" };
    let output = Command::new(python)
        .arg(script)
        .arg("--se")
        .arg(binary)
        .arg("--output")
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

#[cfg(target_os = "linux")]
#[test]
fn runtime_crash_preserves_orphan_until_explicit_forced_relaunch()
-> Result<(), Box<dyn std::error::Error>> {
    judge("crash")
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_crash_never_reaps_a_slow_live_provider() -> Result<(), Box<dyn std::error::Error>> {
    judge("slow")
}

#[test]
fn shared_server_keeps_agent_sessions_separate_and_stops_with_the_last()
-> Result<(), Box<dyn std::error::Error>> {
    judge("shared")
}

#[cfg(target_os = "linux")]
#[test]
fn shared_server_preserves_the_native_process_when_its_record_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    judge("missing-record")
}

#[cfg(target_os = "linux")]
#[test]
fn shared_server_preserves_the_native_process_when_its_record_names_an_earlier_instance()
-> Result<(), Box<dyn std::error::Error>> {
    judge("stale-record")
}

#[cfg(windows)]
#[test]
fn attaches_with_the_selected_login_after_a_host_restart() -> Result<(), Box<dyn std::error::Error>>
{
    judge("other-home-attach")
}
