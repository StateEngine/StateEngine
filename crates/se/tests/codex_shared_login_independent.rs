//! Public CLI verification that multiple Codex agents on one login share one
//! app-server, follow a relinked login file in status without leaking tokens,
//! keep the server alive until the last agent stops, and retire it cleanly.
//! No provider account, real model turn or network access is exercised.
#![cfg(target_os = "linux")]
use std::{path::PathBuf, process::Command};
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn two_codex_agents_share_one_server_follow_relinked_login_and_retire_on_last_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let home = directory::private_case_directory()?;
    let root = home.join("run");
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/judges/codex_shared_login_cli.py");
    let output = Command::new("python3")
        .arg(script)
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "public CLI shared-login verification failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    home.finish(Ok(()))
}
