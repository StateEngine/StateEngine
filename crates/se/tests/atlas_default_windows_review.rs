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
    process::{Child, Command, Stdio},
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

struct ProcessTrace {
    child: Option<Child>,
    root: PathBuf,
}
impl ProcessTrace {
    fn start(root: &Path, image_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                include_str!("support/atlas_default_windows_processes.ps1"),
            ])
            .env("ATLAS_REVIEW_TRACE_DIR", root)
            .env("ATLAS_REVIEW_IMAGE_NAME", image_name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut trace = Self {
            child: Some(child),
            root: root.to_owned(),
        };
        let end = Instant::now() + Duration::from_secs(10);
        while !root.join("trace-pending").try_exists()? {
            if trace.child.as_mut().unwrap().try_wait()?.is_some() {
                let output = trace.child.take().unwrap().wait_with_output()?;
                return Err(format!(
                    "native process trace refused: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            if Instant::now() >= end {
                return Err("native process trace did not arm".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Ok(trace)
    }
    fn finish(mut self) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        fs::write(self.root.join("trace-finish"), b"")?;
        let output = self.child.take().unwrap().wait_with_output()?;
        let json = checked(output)?;
        Ok(serde_json::from_value(json)?)
    }
}
impl Drop for ProcessTrace {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = fs::write(self.root.join("trace-finish"), b"");
            let _ = child.wait();
        }
    }
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
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let image_name = format!("a{}.exe", &nonce[..8]);
    let image = f.home.join(&image_name);
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
    let trace = ProcessTrace::start(&f.home, &image_name)?;
    let host = runtime_host::RunningHost::start(&image, home)?;
    let endpoint =
        se_host::client::endpoint::decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
    let pid = u64::from(endpoint.epoch.owner.fields().pid.get());
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
    let query = command(&image, home, true)
        .current_dir(&root)
        .args(["atlas", "find", "review_marker"])
        .output_executable()?;
    let query_text = format!(
        "{}{}",
        String::from_utf8_lossy(&query.stdout),
        String::from_utf8_lossy(&query.stderr)
    );
    let cache_exists = home.join("atlas").try_exists()?;
    host.stop()?;
    let starts = trace.finish()?;
    let host_seen = starts
        .iter()
        .any(|start| start["pid"].as_u64() == Some(pid));
    let children: Vec<_> = starts
        .iter()
        .filter(|start| start["parent_pid"].as_u64() == Some(pid))
        .collect();
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    fs::create_dir_all(&out)?;
    fs::write(
        out.join("atlas-default-windows.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "observations":states,"atlas_cache_directory_exists":cache_exists,
            "process_trace": {"host_seen":host_seen,"host_pid":pid,"candidate_starts":starts,"host_children":children},
            "query": {"exit":query.status.code(),"text":query_text}
        }))?,
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
    assert!(
        host_seen,
        "the exact host start was absent from the process trace: {starts:?}"
    );
    assert!(
        children.is_empty(),
        "default spawned an extra candidate process: {children:?}"
    );
    assert!(!cache_exists, "default created Atlas index state");
    assert!(
        query_text
            .to_ascii_lowercase()
            .contains("not yet qualified"),
        "query omitted the Windows qualification reason: {query_text}"
    );
    Ok(())
}
