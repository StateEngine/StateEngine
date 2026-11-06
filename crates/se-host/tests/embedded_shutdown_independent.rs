//! Real linked host + external lock observer. Run only with the exact native
//! CLI supplied through SE_SHUTDOWN_JUDGE_SE, inside the admitted install slot.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "support/shutdown_linked_fixture.rs"]
mod support;
use secode_stateengine_api as api;
use std::{
    fs,
    io::{BufRead, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use support::*;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn control_file(root: &Path) -> PathBuf {
    root.join("observed.json")
}
fn check(ok: bool, reason: &str) -> Check {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn helper() -> Check<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os("SE_SHUTDOWN_JUDGE_SE")
            .ok_or("SE_SHUTDOWN_JUDGE_SE must pin a built native CLI; no check was run")?,
    );
    check(
        path.is_absolute() && path.is_file(),
        "native CLI path is unavailable",
    )?;
    Ok(path)
}
fn child_case(root: &Path, image: &Path) -> Check {
    let home = root.join("state");
    let repo = root.join("repo");
    fs::create_dir(&repo)?;
    let init = Command::new(image)
        .args(["init", "--home"])
        .arg(&home)
        .arg("--repo")
        .arg(&repo)
        .args([
            "--name",
            "Embedded shutdown judge",
            "--agent",
            "Judge",
            "--provider",
            "claude",
            "--model",
            "claude-sonnet-5-5",
            "--json",
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH absent")?)
        .env("HOME", root)
        .env("USERPROFILE", root)
        .output()?;
    check(
        init.status.success(),
        &format!(
            "native init failed: {} {}",
            String::from_utf8_lossy(&init.stdout),
            String::from_utf8_lossy(&init.stderr)
        ),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    // The owner thread drives this public handle; no Tokio worker runtime is
    // created by the product. Main-thread block_on keeps timers alive.
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let config = api::HostConfig { state_home: home.clone(), helper_executable: image.into(),
            linux_delegation: api::LinuxDelegation::CurrentScope, api: api::API_VERSION,
            kind: api::HostKind::EmbeddedSecode, features: vec![api::Feature::LocalListener],
            limits: api::Limits { page_items: std::num::NonZeroU32::MIN.saturating_add(99), payload_bytes: std::num::NonZeroU32::MIN.saturating_add(262143), notice_ids: std::num::NonZeroU32::MIN.saturating_add(99) } };
        let opened = factory.open(config, api::OpenOptions { expected_generation: None, timeout: Duration::from_secs(20), cancellation: Arc::new(NoopCancellation) }).await.map_err(|e| format!("embedded open: {e:?}"))?;
        let api::Read::Present { value: opened } = opened else { return Err("initialized embedded store was not present".into()); };
        let options = call_options(opened.negotiated.generation, Duration::from_secs(20));
        let epoch = build_epoch(opened.negotiated.generation.0, &home)?;
        let ready = opened.host.activate(api::HostIntegration::Secode { epoch, services: Arc::new(SilentServices) }, options.clone()).await.map_err(|e| format!("embedded activate: {e:?}"))?;
        check(ready == api::Readiness::Ready, "embedded host never became Ready")?;
        if std::env::var_os("SE_SHUTDOWN_JUDGE_POSITIVE").is_some() {
            fs::write(root.join("ready.json"), serde_json::to_vec(&serde_json::json!({"generation":opened.negotiated.generation.0,"pid":std::process::id()}))?)?;
            let until = Instant::now() + Duration::from_secs(120);
            while !root.join("observer-finished").try_exists()? {
                check(Instant::now() < until, "outside positive observer timed out")?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let drained = opened.host.drain(options.clone()).await.map_err(|e| format!("positive drain: {e:?}"))?;
            let repeat = opened.host.drain(options.clone()).await.map_err(|e| format!("positive repeated drain: {e:?}"))?;
            let closed = opened.host.close(drained.clone(), options).await.map_err(|e| format!("positive close: {e:?}"))?;
            fs::write(control_file(root),serde_json::to_vec_pretty(&serde_json::json!({"writer_flushed":drained.writer_flushed,"unresolved_effects":drained.unresolved_effects,"repeat_identical":repeat==drained,"close_identical":closed==drained,"health":format!("{:?}",opened.host.health())}))?)?;
            return Ok(());
        }
        // Fault producer is another native process, after activation. The
        // production shutdown reader must retain unreadable inventory as debt.
        let fault = Command::new("python3").arg("-c").arg("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('ALTER TABLE processes RENAME TO processes_unreadable_fixture'); c.commit()")
            .arg(home.join("state.db")).status()?;
        check(fault.success(), "external inventory fault producer failed")?;
        let drained = opened.host.drain(options.clone()).await.map_err(|e| format!("embedded drain: {e:?}"))?;
        let repeat = opened.host.drain(options.clone()).await.map_err(|e| format!("repeated embedded drain: {e:?}"))?;
        let close = opened.host.close(drained.clone(), options).await;
        let result = serde_json::json!({ "writer_flushed": drained.writer_flushed,
            "unresolved_effects": drained.unresolved_effects, "pending_notices": drained.pending_notices,
            "repeat_identical": repeat == drained, "health": format!("{:?}", opened.host.health()),
            "close_refused": close.is_err(), "close_error": format!("{close:?}") });
        fs::write(control_file(root), serde_json::to_vec_pretty(&result)?)?;
        // The external parent now probes the lease while this application and
        // the poisoned owner thread are still alive. No signal or forced stop.
        let mut input = String::new(); std::io::stdin().lock().read_line(&mut input)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    // The intentionally parked native owner retains this handle until the
    // test application exits naturally. Dropping a runtime would wait forever.
    std::mem::forget(runtime);
    Ok(())
}
#[test]
#[ignore = "owned subprocess fixture, invoked only by the external observer"]
fn poisoned_embedded_child() -> Check {
    let root =
        PathBuf::from(std::env::var_os("SE_SHUTDOWN_JUDGE_ROOT").ok_or("fixture root absent")?);
    child_case(&root, &helper()?)
}
#[test]
fn failed_linked_drain_refuses_close_and_retains_lease_until_application_exit() -> Check {
    let image = helper()?;
    let entropy = se_proc::random_secret().map_err(|e| format!("fixture entropy: {e:?}"))?;
    let root = std::env::temp_dir().join(format!(
        "se-ec-{}-{}",
        std::process::id(),
        se_types::hex_lower(&entropy.expose()[..8])
    ));
    fs::create_dir(&root)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "poisoned_embedded_child",
            "--nocapture",
        ])
        .env("SE_SHUTDOWN_JUDGE_SE", &image)
        .env("SE_SHUTDOWN_JUDGE_ROOT", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let observation = (|| -> Check<serde_json::Value> {
        let until = Instant::now() + Duration::from_secs(100);
        while !control_file(&root).try_exists()? {
            if let Some(status) = child.try_wait()? {
                return Err(format!(
                    "embedded fixture {} exited before observation: {status}; retained {}",
                    child.id(),
                    root.display()
                )
                .into());
            }
            check(
                Instant::now() < until,
                "embedded fixture observation timed out",
            )?;
            std::thread::park_timeout(Duration::from_millis(10));
        }
        let mut value: serde_json::Value = serde_json::from_slice(&fs::read(control_file(&root))?)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("state/runtime.lock"))?;
        value["outside_lease_held"] =
            matches!(lock.try_lock(), Err(fs::TryLockError::WouldBlock)).into();
        value["outside_endpoint_absent"] = (!root.join("state/endpoint.json").try_exists()?).into();
        Ok(value)
    })();
    // Settle our exact child before any assertion, including a red result.
    let input_result = child
        .stdin
        .take()
        .map(|mut input| input.write_all(b"observer finished\n"));
    let status = child.wait()?;
    if let Some(result) = input_result {
        result?;
    }
    let observed = observation?;
    fs::write(
        root.join("outside.json"),
        serde_json::to_vec_pretty(&observed)?,
    )?;
    check(status.success(), "owned embedded application failed")?;
    check(
        observed["writer_flushed"] == false
            && observed["unresolved_effects"]
                .as_u64()
                .is_some_and(|v| v > 0),
        "failed inventory became a flushed drain",
    )?;
    check(
        observed["health"] == "Poisoned"
            && observed["close_refused"] == true
            && observed["repeat_identical"] == true,
        "failed drain lost poison, changed on replay, or closed",
    )?;
    check(
        observed["outside_lease_held"] == true && observed["outside_endpoint_absent"] == true,
        "poisoned application dropped native custody or endpoint retirement failed",
    )?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("state/runtime.lock"))?;
    lock.try_lock()
        .map_err(|e| format!("exact application exited but lease remains: {e}"))?;
    drop(lock);
    eprintln!(
        "embedded negative control passed; readbacks retained at {}",
        root.display()
    );
    Ok(())
}

/// Protects: public CLI down proves resource closure and releases the lease
/// while the embedding application is still alive; API drain/close replay it.
#[test]
fn public_down_closes_an_embedded_host_without_claiming_application_exit() -> Check {
    let image = helper()?;
    let entropy =
        se_proc::random_secret().map_err(|e| format!("positive fixture entropy: {e:?}"))?;
    let key = format!(
        "embedded-positive-{}",
        se_types::hex_lower(&entropy.expose()[..12])
    );
    let root = std::env::temp_dir().join(format!(
        "se-ep-{}-{}",
        std::process::id(),
        se_types::hex_lower(&entropy.expose()[..8])
    ));
    fs::create_dir(&root)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "poisoned_embedded_child",
            "--nocapture",
        ])
        .env("SE_SHUTDOWN_JUDGE_SE", &image)
        .env("SE_SHUTDOWN_JUDGE_ROOT", &root)
        .env("SE_SHUTDOWN_JUDGE_POSITIVE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let observed = (|| -> Check<serde_json::Value> {
        let until = Instant::now() + Duration::from_secs(100);
        while !root.join("ready.json").try_exists()? {
            if let Some(status) = child.try_wait()? {
                return Err(
                    format!("positive application exited before readiness: {status}").into(),
                );
            }
            check(Instant::now() < until, "positive readiness timed out")?;
            std::thread::park_timeout(Duration::from_millis(10));
        }
        let output = Command::new(&image)
            .args(["down", "--home"])
            .arg(root.join("state"))
            .args(["--key", &key, "--json"])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").ok_or("PATH absent")?)
            .env("HOME", &root)
            .env("USERPROFILE", &root)
            .output()?;
        fs::write(root.join("down.stdout"), &output.stdout)?;
        fs::write(root.join("down.stderr"), &output.stderr)?;
        let files = se_host::state_files::Files::open(&root.join("state"))?;
        let receipt = se_host::client::closure::read(&files, &root.join("state"))?;
        let probe = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("state/runtime.lock"))?;
        let held = matches!(probe.try_lock(), Err(fs::TryLockError::WouldBlock));
        let alive = child.try_wait()?.is_none();
        fs::write(
            root.join("before-api-cleanup.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "application_alive":alive,"outside_lease_held":held,"endpoint_absent":!root.join("state/endpoint.json").try_exists()?,
                "matching_key":receipt.as_ref().is_some_and(|v|v.key.as_str()==key),"resources_closed":receipt.as_ref().map(|v|v.resources_closed)
            }))?,
        )?;
        drop(probe);
        check(
            output.status.success(),
            "public embedded down failed; original output retained",
        )?;
        let down: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        check(
            down["schema"] == "se.runtime-stop/v1"
                && down["complete"] == true
                && down["witness"]["state"] == "witnessed",
            "embedded down did not report complete witnessed closure",
        )?;
        check(
            child.try_wait()?.is_none(),
            "public down terminated the embedding application",
        )?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("state/runtime.lock"))?;
        lock.try_lock()
            .map_err(|e| format!("complete embedded down retained the OS lease: {e}"))?;
        check(
            !root.join("state/endpoint.json").try_exists()?,
            "embedded endpoint remains under exclusive lease",
        )?;
        let files = se_host::state_files::Files::open(&root.join("state"))?;
        let receipt = se_host::client::closure::read(&files, &root.join("state"))?
            .ok_or("protected closure receipt absent")?;
        check(
            receipt.key.as_str() == key && receipt.resources_closed,
            "protected receipt lost original key or resource closure",
        )?;
        Ok(
            serde_json::json!({"application_alive":true,"outside_lease_free":true,"outside_endpoint_absent":true,"original_key":key,"resources_closed":receipt.resources_closed}),
        )
    })();
    fs::write(
        root.join("observer-finished"),
        b"outside observer settled\n",
    )?;
    let status = child.wait()?;
    check(status.success(), "positive embedded application failed")?;
    let observed = observed?;
    fs::write(
        root.join("outside.json"),
        serde_json::to_vec_pretty(&observed)?,
    )?;
    let api: serde_json::Value = serde_json::from_slice(&fs::read(control_file(&root))?)?;
    check(
        api["writer_flushed"] == true
            && api["unresolved_effects"] == 0
            && api["repeat_identical"] == true
            && api["close_identical"] == true
            && api["health"] == "Closed",
        "positive API completion/replay differs from the outside closure",
    )?;
    eprintln!(
        "positive embedded closure passed; readbacks retained at {}",
        root.display()
    );
    Ok(())
}
