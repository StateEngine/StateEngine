#![cfg(windows)]
#![allow(
    dead_code,
    reason = "The native fixtures share setup and readback helpers."
)]

#[path = "../../test-support/executable.rs"]
mod executable;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "support/runtime_host.rs"]
mod runtime_host;

use executable::ExecutableCommand;
use fixture::{Check, Fixture};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

fn command(image: &Path, home: &Path, json: bool) -> Command {
    let mut command = Command::new(image);
    if json {
        command.arg("--json");
    }
    command.arg("--home").arg(home);
    for name in [
        "SE_HOME",
        "SE_PROJECT",
        "SE_CONFIG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    command
}

fn checked(output: std::process::Output) -> Result<Value, Box<dyn std::error::Error>> {
    if !output.status.success() {
        return Err(format!(
            "CLI refused: {}; {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn windows_default_reports_atlas_unavailable_before_starting_index_work() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let root = f.home.join("atlas-project");
    fs::create_dir(&root)?;
    fs::write(
        root.join("sample.js"),
        "export function review_marker() {}\n",
    )?;
    let image = f.home.join("candidate.exe");
    let candidate = std::env::var_os("SE_W3_SE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_se")));
    fs::copy(candidate, &image)?;
    checked(
        command(&image, home, true)
            .current_dir(&root)
            .args(["init", "--repo"])
            .arg(&root)
            .args(["--name", "atlas-default-review"])
            .output_executable()?,
    )?;
    let host = runtime_host::RunningHost::start(&image, home)?;
    assert!(host.live()?);
    let end = Instant::now() + Duration::from_secs(6);
    let mut states = Vec::new();
    loop {
        let status = checked(
            command(&image, home, true)
                .current_dir(&root)
                .arg("status")
                .output_executable()?,
        )?;
        assert_eq!(status["project"]["state"], "present");
        let observed = status["atlas"].clone();
        if states.last() != Some(&observed) {
            states.push(observed);
        }
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let cache_exists = home.join("atlas").try_exists()?;
    host.stop()?;
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    fs::create_dir_all(&out)?;
    fs::write(
        out.join("atlas-default-windows.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"observations":states,"atlas_cache_directory_exists":cache_exists}),
        )?,
    )?;
    let settled = states.last().ok_or("Atlas status observations absent")?;
    assert!(
        matches!(settled["state"].as_str(), Some("disabled" | "unavailable")),
        "expected Atlas unavailable under the default Windows install: {states:#?}"
    );
    assert!(
        settled["reason"].as_str().is_some_and(|reason| {
            let reason = reason.to_ascii_lowercase();
            reason.contains("qualif") || reason.contains("not enabled")
        }),
        "missing reason for unavailable Windows Atlas: {settled}"
    );
    assert!(
        !states
            .iter()
            .any(|status| status["summary"]["state"].get("ColdIndexing").is_some()),
        "default started an Atlas worker: {states:#?}"
    );
    assert!(!cache_exists, "default created Atlas index state");
    Ok(())
}
