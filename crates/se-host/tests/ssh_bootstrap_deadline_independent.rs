//! Observe the shipping SSH command with native disposable client processes.
#![cfg(all(windows, feature = "remote"))]

#[allow(dead_code, unused_imports)]
#[path = "../src/ssh_transport/mod.rs"]
mod shipping;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require(condition: bool, message: impl Into<String>) -> Check {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}

#[tokio::test]
#[ignore = "isolated subprocess entry; the observer supplies a private client PATH"]
async fn native_probe_entry() -> Check {
    let root = PathBuf::from(std::env::var_os("SE_SSH_CAPTURE_REVIEW_ROOT").ok_or("root absent")?);
    let mode = std::env::var("SE_SSH_CAPTURE_REVIEW_MODE")?;
    let observed = match shipping::command("localhost", mode).await {
        Ok(value) => json!({"kind":"completed", "success":value.success,
            "stdout":value.stdout, "stderr_tail":value.stderr_tail}),
        Err(error) => match error.body.detail() {
            se_types::Detail::ListenerUnavailable(detail) => json!({"kind":"refusal",
                "reason":detail.reason, "next_step":detail.next_step}),
            _ => json!({"kind":"other-error", "error":format!("{error:?}")}),
        },
    };
    fs::write(
        root.join("observed.json"),
        serde_json::to_vec_pretty(&observed)?,
    )?;
    Ok(())
}

fn observe(mode: &str) -> Check<Value> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics")
        .join(format!("ssh-capture-{mode}-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root)?;
    let normalized = root.canonicalize()?.to_string_lossy().into_owned();
    let root = PathBuf::from(normalized.strip_prefix(r"\\?\").unwrap_or(&normalized));
    let helper_source = root.join("CaptureClient.cs");
    fs::write(
        &helper_source,
        include_bytes!("support/ssh_capture_client.cs"),
    )?;
    let helper = root.join("ssh.exe");
    let compiler = PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot absent")?)
        .join("Microsoft.NET/Framework64/v4.0.30319/csc.exe");
    let compiled = Command::new(compiler)
        .args(["/nologo", "/target:exe"])
        .arg(format!("/out:{}", helper.display()))
        .arg(&helper_source)
        .output()?;
    fs::write(root.join("compiler.stdout"), &compiled.stdout)?;
    fs::write(root.join("compiler.stderr"), &compiled.stderr)?;
    require(
        compiled.status.success(),
        "native client fixture failed to compile",
    )?;
    let mut paths = vec![root.clone()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").ok_or("PATH absent")?,
    ));
    let status = Command::new(std::env::current_exe()?)
        .args(["--exact", "native_probe_entry", "--ignored", "--nocapture"])
        .env("PATH", std::env::join_paths(paths)?)
        .env("SE_SSH_CAPTURE_REVIEW_ROOT", &root)
        .env("SE_SSH_CAPTURE_REVIEW_MODE", mode)
        .env("SE_SSH_CAPTURE_REVIEW_PIDS", root.join("helper-pids.txt"))
        .stdout(fs::File::create(root.join("probe.stdout"))?)
        .stderr(fs::File::create(root.join("probe.stderr"))?)
        .status()?;
    // This observer is outside the runtime that owned the client and its pipes.
    let pids = fs::read_to_string(root.join("helper-pids.txt"))?;
    let rows: Vec<_> = pids.lines().collect();
    require(
        rows.len() == 1,
        format!("expected one client instance: {pids:?}"),
    )?;
    let fields: Vec<_> = rows[0].splitn(3, '|').collect();
    require(fields.len() == 3, "client instance record incomplete")?;
    let pid: u32 = fields[0].parse()?;
    let birth: u64 = fields[1].parse()?;
    require(
        fields[2].eq_ignore_ascii_case(&helper.to_string_lossy()),
        "client image differs",
    )?;
    let script = format!(
        "try {{$p=Get-Process -Id {pid} -ErrorAction Stop; @{{state='present';pid=$p.Id;birth=$p.StartTime.ToUniversalTime().ToFileTimeUtc();image=$p.Path}}|ConvertTo-Json -Compress}} catch {{if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId*') {{@{{state='absent'}}|ConvertTo-Json -Compress}} else {{@{{state='unreadable';error=$_.Exception.Message}}|ConvertTo-Json -Compress}}}}"
    );
    let census = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()?;
    fs::write(root.join("census.stdout"), &census.stdout)?;
    fs::write(root.join("census.stderr"), &census.stderr)?;
    require(census.status.success(), "outside process census failed")?;
    let row: Value = serde_json::from_slice(&census.stdout)?;
    let absent = row["state"] == "absent"
        || (row["state"] == "present" && row["birth"].as_u64().is_some_and(|b| b != birth));
    let source = Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()?;
    require(source.status.success(), "source revision unreadable")?;
    let source = String::from_utf8(source.stdout)?.trim().to_owned();
    let receipt = json!({"mode":mode,"probe_exit":status.code(),"expected_pid":pid,
        "expected_birth":birth,"outside_census":row,"helper_absent":absent,
        "source":source,"platform":std::env::consts::OS,
        "shipping_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("../src/ssh_transport/mod.rs"))),
        "test_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("ssh_bootstrap_deadline_independent.rs"))),
        "helper_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("support/ssh_capture_client.cs"))),
        "helper_image_sha256":format!("{:x}",Sha256::digest(fs::read(&helper)?))});
    fs::write(
        root.join("census.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    require(absent, format!("client was not witnessed gone: {receipt}"))?;
    require(
        status.success(),
        "isolated native probe failed; retain its logs",
    )?;
    let observed: Value = serde_json::from_slice(&fs::read(root.join("observed.json"))?)?;
    println!("{}", json!({"receipt":root,"observed":observed}));
    Ok(observed)
}

#[test]
fn closed_pipes_retain_captured_counts_until_client_exit() -> Check {
    let value = observe("closed")?;
    let reason = value["reason"].as_str().ok_or("deadline reason absent")?;
    require(reason.contains("5 stdout bytes (pipe closed)"), reason)?;
    require(reason.contains("4 stderr bytes (pipe closed)"), reason)?;
    require(reason.contains("was still running"), reason)
}

#[test]
fn open_pipes_retain_partial_counts_and_client_state() -> Check {
    let value = observe("open")?;
    let reason = value["reason"].as_str().ok_or("deadline reason absent")?;
    require(reason.contains("5 stdout bytes (pipe still open)"), reason)?;
    require(reason.contains("4 stderr bytes (pipe still open)"), reason)?;
    require(reason.contains("was still running"), reason)
}

#[test]
fn bootstrap_refusal_offers_a_bootstrap_remedy() -> Check {
    let value = observe("open")?;
    let step = value["next_step"].as_str().ok_or("next step absent")?;
    require(!step.contains("retrying a send"), step)?;
    let lower = step.to_ascii_lowercase();
    require(lower.contains("ssh") || lower.contains("bootstrap"), step)
}

#[test]
fn completed_client_keeps_output_and_status() -> Check {
    let value = observe("complete")?;
    require(
        value["kind"] == "completed" && value["success"] == true,
        value.to_string(),
    )?;
    require(
        value["stdout"] == json!(b"hello".to_vec()),
        value.to_string(),
    )?;
    require(value["stderr_tail"] == "note", value.to_string())
}

#[test]
fn oversized_stdout_refuses_while_client_remains_alive() -> Check {
    let value = observe("overflow")?;
    require(
        value["reason"] == "SSH output exceeded its bounded bootstrap response",
        value.to_string(),
    )
}
