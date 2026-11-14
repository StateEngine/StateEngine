//! Protects: 50 A.3 / B5 — CLI and serving hosts use canonical names; only
//! hosted status supplies real self-accounting, including the embedded mirror.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "support/shutdown_linked_fixture.rs"]
mod linked_fixture;
use linked_fixture::*;
use se_host::{
    IpcEnvelope, IpcRequest, RawOperation,
    client::{
        BlockingIpcClient, ClientOptions, endpoint::decode_endpoint, lease::ClientCredential,
    },
};
use secode_stateengine_api as api;
use serde_json::{Value, json};
use std::{
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn image(name: &str) -> Check<PathBuf> {
    let value =
        PathBuf::from(std::env::var_os(name).ok_or(format!("{name} must pin a real native CLI"))?);
    if !value.is_absolute() || !value.is_file() {
        return Err(format!("{name} unavailable").into());
    }
    Ok(value)
}
fn root(label: &str) -> Check<PathBuf> {
    let secret = se_proc::random_secret().map_err(|e| format!("entropy: {e:?}"))?;
    let parent = std::env::var_os("SE_RUNTIME_JUDGE_OUT")
        .map(PathBuf::from)
        .ok_or("SE_RUNTIME_JUDGE_OUT must name a private artifact directory")?;
    let name = format!("{label}-{}", se_types::hex_lower(&secret.expose()[..8]));
    // Native Unix sockets are bounded; raw state needs a short protected root,
    // while the caller's deep artifact directory retains its exact location.
    let value = std::env::temp_dir().join(format!("se-rs-{name}"));
    fs::create_dir(&value)?;
    let root_owner = cleanup_directory::PrivateDirectory::adopt(value.clone());
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&value, fs::Permissions::from_mode(0o700))?;
    fs::write(
        parent.join(format!("{name}.fixture.json")),
        serde_json::to_vec(&json!({"root":value}))?,
    )?;
    root_owner.retain("native status evidence is retained on failure");
    Ok(value)
}
fn cleanup(root: &Path) -> Check {
    let artifacts =
        PathBuf::from(std::env::var_os("SE_RUNTIME_JUDGE_OUT").ok_or("artifact directory absent")?);
    let name = root
        .file_name()
        .ok_or("fixture name absent")?
        .to_string_lossy();
    fs::copy(
        root.join("status.json"),
        artifacts.join(format!("{name}.status.json")),
    )?;
    fs::remove_dir_all(root)?;
    Ok(())
}
fn command(image: &Path, home: &Path, args: &[&str]) -> Command {
    let mut value = Command::new(image);
    value
        .arg("--home")
        .arg(home)
        .args(args)
        .arg("--json")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home.parent().unwrap_or(home))
        .env("XDG_RUNTIME_DIR", "/run/user/1000");
    value
}
fn cli(image: &Path, home: &Path, args: &[&str]) -> Check<Value> {
    let output = command(image, home, args).output()?;
    if !output.status.success() {
        return Err(format!(
            "public CLI failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn initialize(image: &Path, root: &Path) -> Check<PathBuf> {
    let repo = root.join("repo");
    fs::create_dir(&repo)?;
    fs::write(repo.join("user.txt"), "Keep user work.\n")?;
    let home = root.join("state");
    cli(
        image,
        &home,
        &[
            "init",
            "--repo",
            repo.to_str().ok_or("non-UTF8 fixture")?,
            "--name",
            "status-judge",
            "--agent",
            "judge",
            "--provider",
            "claude",
        ],
    )?;
    Ok(home)
}
fn hosted(home: &Path) -> Check<Value> {
    let endpoint = decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let mut connection = BlockingIpcClient::connect_authenticated(
        &endpoint,
        ClientCredential::Machine(se_types::Secret::new(fs::read(home.join("credential"))?)?),
        NonZeroU32::new(1_048_576).ok_or("zero reply budget")?,
        &options,
    )?;
    let response = connection.exchange(
        IpcEnvelope {
            version: connection.negotiated().version,
            request_id: 1,
            generation: endpoint.generation,
            authority: None,
            presence: None,
            cli_selections: None,
            request: IpcRequest::Operation(RawOperation {
                name: "project.status".into(),
                arguments: json!({}),
                key: None,
            }),
        },
        &options,
    )?;
    if response.schema != "se.status/v1" {
        return Err("wrong hosted status family".into());
    }
    Ok(response.value)
}

/// Protects: B5/B6 — the external idle runner samples the actual public host
/// reader, without making the direct CLI pretend to know another PID's rusage.
#[test]
#[ignore = "public IPC adapter invoked by runtime_idle.mjs with an owned home"]
fn hosted_status_reader() -> Check {
    let home = PathBuf::from(std::env::var_os("SE_RUNTIME_JUDGE_HOME").ok_or("owned home absent")?);
    let reply = PathBuf::from(
        std::env::var_os("SE_RUNTIME_JUDGE_REPLY").ok_or("private reply path absent")?,
    );
    let value = hosted(&home)?;
    use std::io::Write;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(reply)?;
    output.write_all(&serde_json::to_vec(&value)?)?;
    Ok(())
}
fn inspect(direct: &Value, served: &Value, name: &str, pid: u32) -> Vec<String> {
    let mut failures = vec![];
    for (surface, value) in [("direct", direct), ("hosted", served)] {
        if value["runtime"]["host"] != name {
            failures.push(format!(
                "{surface} runtime.host: expected {name}, got {}",
                value["runtime"]["host"]
            ));
        }
        if value["runtime"]["process"]["pid"] != pid {
            failures.push(format!(
                "{surface} status did not name exact native host {pid}"
            ));
        }
    }
    if direct["runtime"].get("resources").is_some() {
        failures.push("direct file-only status invented host self-accounting".into());
    }
    let Some(resources) = served["runtime"]
        .get("resources")
        .and_then(Value::as_object)
    else {
        failures.push("hosted resources unavailable; not a zero measurement".into());
        return failures;
    };
    for field in [
        "self_voluntary_switches",
        "self_involuntary_switches",
        "cpu_user_us",
        "cpu_system_us",
        "rss_bytes",
    ] {
        if resources.get(field).and_then(Value::as_u64).is_none() {
            failures.push(format!("hosted kernel counter missing/invalid: {field}"));
        }
    }
    if resources.get("method") != Some(&json!("linux:getrusage(RUSAGE_SELF)+/proc/self/statm")) {
        failures.push("wrong Linux self-accounting source".into());
    }
    if resources
        .get("sampled_at")
        .and_then(Value::as_str)
        .is_none()
    {
        failures.push("self-accounting sample timestamp absent".into());
    }
    if resources.get("rss_bytes").and_then(Value::as_u64) == Some(0) {
        failures.push("live host RSS falsely zero".into());
    }
    failures
}
fn outside_closed(root: &Path, home: &Path) -> Check {
    if home.join("endpoint.json").try_exists()? {
        return Err("host endpoint remains after shutdown".into());
    }
    let file = fs::File::open(home.join("runtime.lock"))?;
    file.try_lock()?;
    if fs::read_to_string(root.join("repo/user.txt"))? != "Keep user work.\n" {
        return Err("user work changed".into());
    }
    Ok(())
}

#[test]
/// Protects: 50 A.3 — standalone CLI/IPC names agree and only IPC reports host counters.
fn standalone_direct_and_hosted_status_obey_section_50() -> Check {
    let binary = image("SE_RUNTIME_JUDGE_SE")?;
    let setup = std::env::var_os("SE_RUNTIME_JUDGE_SETUP_SE")
        .map(PathBuf::from)
        .unwrap_or(binary.clone());
    let root = root("daemon")?;
    let home = initialize(&setup, &root)?;
    let absent = cli(&binary, &home, &["status"])?;
    assert!(absent["runtime"]["host"].is_null());
    cli(&binary, &home, &["up"])?;
    let observation = (|| -> Check<_> {
        let direct = cli(&binary, &home, &["status"])?;
        let served = hosted(&home)?;
        let endpoint = decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
        let pid = endpoint.epoch.owner.fields().pid.get();
        fs::write(
            root.join("status.json"),
            serde_json::to_vec_pretty(&json!({"direct":direct,"hosted":served,"native_pid":pid}))?,
        )?;
        Ok(inspect(&direct, &served, "daemon", pid))
    })();
    let stopped = cli(&binary, &home, &["down"]);
    stopped?;
    outside_closed(&root, &home)?;
    let failures = observation?;
    assert!(
        failures.is_empty(),
        "{}; raw {}",
        failures.join("; "),
        root.display()
    );
    cleanup(&root)
}

#[test]
/// Protects: 50 A.3 — embedded CLI/IPC names agree without changing the direct-read contract.
fn embedded_direct_and_hosted_status_obey_section_50() -> Check {
    let binary = image("SE_RUNTIME_JUDGE_SE")?;
    let setup = std::env::var_os("SE_RUNTIME_JUDGE_SETUP_SE")
        .map(PathBuf::from)
        .unwrap_or(binary.clone());
    let root = root("secode")?;
    let home = initialize(&setup, &root)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let config = api::HostConfig {
            state_home: home.clone(),
            helper_executable: binary.clone(),
            linux_delegation: api::LinuxDelegation::CurrentScope,
            api: api::API_VERSION,
            kind: api::HostKind::EmbeddedSecode,
            features: vec![api::Feature::LocalListener],
            limits: api::Limits {
                page_items: NonZeroU32::MIN.saturating_add(99),
                payload_bytes: NonZeroU32::MIN.saturating_add(262143),
                notice_ids: NonZeroU32::MIN.saturating_add(99),
            },
        };
        let opened = factory
            .open(
                config,
                api::OpenOptions {
                    expected_generation: None,
                    timeout: Duration::from_secs(30),
                    cancellation: Arc::new(NoopCancellation),
                },
            )
            .await
            .map_err(|e| format!("public embedded open: {e:?}"))?;
        let api::Read::Present { value: opened } = opened else {
            return Err("initialized host absent".into());
        };
        let options = call_options(opened.negotiated.generation, Duration::from_secs(30));
        let epoch = build_epoch(opened.negotiated.generation.0, &home)?;
        opened
            .host
            .activate(
                api::HostIntegration::Secode {
                    epoch,
                    services: Arc::new(SilentServices),
                },
                options.clone(),
            )
            .await
            .map_err(|e| format!("public embedded activate: {e:?}"))?;
        let observe_home = home.clone();
        let observe_binary = binary.clone();
        let observation = tokio::task::spawn_blocking(move || -> Result<(Value, Value), String> {
            Ok((
                cli(&observe_binary, &observe_home, &["status"]).map_err(|e| e.to_string())?,
                hosted(&observe_home).map_err(|e| e.to_string())?,
            ))
        })
        .await?;
        let drained = opened
            .host
            .drain(options.clone())
            .await
            .map_err(|e| format!("embedded drain: {e:?}"))?;
        opened
            .host
            .close(drained, options)
            .await
            .map_err(|e| format!("embedded close: {e:?}"))?;
        let (direct, served) = observation?;
        fs::write(
            root.join("status.json"),
            serde_json::to_vec_pretty(
                &json!({"direct":direct,"hosted":served,"native_pid":std::process::id()}),
            )?,
        )?;
        outside_closed(&root, &home)?;
        let failures = inspect(&direct, &served, "secode", std::process::id());
        assert!(
            failures.is_empty(),
            "{}; raw {}",
            failures.join("; "),
            root.display()
        );
        cleanup(&root)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
