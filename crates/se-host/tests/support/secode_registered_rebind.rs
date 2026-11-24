//! Native registered-service restart, without a managed Windows launch.
use super::*;
use se_store::*;
use std::{io::Write, path::Path, time::Duration};
#[path = "../../../se/tests/support/secode_rebind_fixture/server.rs"]
#[allow(
    dead_code,
    clippy::duplicate_mod,
    reason = "the native fixture uses the same contract service"
)]
mod server;
#[path = "wave2_host_fixture.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "independent native fixture shares store helpers"
)]
mod support;
use support::*;
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
#[ignore = "spawned as the registered native fixture"]
fn fixture_child() -> Check {
    if let Some(home) = std::env::var_os("SE_REBIND_REJECT_HOME") {
        let record = crate::client::endpoint::decode_endpoint(&std::fs::read(
            PathBuf::from(home).join("endpoint.json"),
        )?)?;
        let project = std::env::var("SE_REBIND_REJECT_PROJECT")?.parse()?;
        let agent = std::env::var("SE_REBIND_REJECT_AGENT")?.parse()?;
        let outcome = crate::client::BlockingIpcClient::rebind(
            &record,
            &support::options(),
            project,
            agent,
            "http://127.0.0.1:43123/".into(),
        );
        let error = outcome.err().ok_or("unregistered image was admitted")?;
        if !error.to_string().contains("not registered") {
            return Err(format!("unexpected image refusal: {error}").into());
        }
        return Ok(());
    }
    let replacement = std::env::var_os("SE_REBIND_PROFILE");
    let profile = match replacement.as_ref() {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(std::env::var_os("SECODE_CONFIG").ok_or("profile absent")?)
            .parent()
            .ok_or("profile parent absent")?
            .to_owned(),
    };
    server::serve(profile, replacement.is_some())
}

fn seed_session(f: &Fixture) -> Check<se_types::SessionId> {
    let (mut direct, lease) = direct(f)?;
    let session = session::session()?;
    let mut prepared = session::prepared(f, &session, &f.a);
    if let EventBody::SessionPrepared { provider, .. } = &mut prepared {
        *provider = Provider::SeCode;
    }
    let now = now()?;
    let mut events = vec![prepared];
    for (purpose, hash) in [("session", [11; 32]), ("http", [12; 32])] {
        events.push(EventBody::CredentialIssued {
            credential: se_core::ops::process_commit::session_credential_id(&session, purpose)?,
            session: session.clone(),
            purpose: purpose.into(),
            secret_sha256: hash,
            expires_at_us: now + 3_600_000_000,
            activation_deadline_us: now + 600_000_000,
            expected: Expected::Absent,
        });
    }
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("registered-prepared")?),
            events,
        )?,
        &*lease,
    )?;
    let mut events = vec![session::activated(&session)?];
    for purpose in ["session", "http"] {
        events.push(EventBody::CredentialActivated {
            credential: se_core::ops::process_commit::session_credential_id(&session, purpose)?,
            session: session.clone(),
            expected: revision(1)?,
            first_request: Some(session::record()?),
        });
    }
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("registered-active")?),
            events,
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    Ok(session)
}

fn private_profile(path: &Path) -> Check {
    #[cfg(unix)]
    drop(se_proc::NativeStateFiles::create(path)?);
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(r#"$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
[System.IO.Directory]::CreateDirectory($env:SE_TEST_PROFILE_PATH, $acl) | Out-Null"#)
            .env("SE_TEST_PROFILE_PATH", path).output()?;
        if !output.status.success() {
            return Err("private fixture profile creation failed".into());
        }
    }
    let files = se_proc::NativeProfileFiles::open(path)?;
    let mut stage = files.create_staging(path)?;
    stage.file.write_all(b"fixture:synthetic-secret\n")?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &path.join("basic.credential"))?;
    Ok(())
}

fn service(f: &Fixture, session: se_types::SessionId, profile: &Path) -> Check<Service> {
    let journal = Journal {
        version: 1,
        retired: false,
        lost: false,
        stop_failure: None,
        project: f.project.clone(),
        agent: f.a.clone(),
        profile: NativePath::from_local(profile.to_path_buf())?,
        session,
        vendor_session: "fixture-session".into(),
        initial_input: "fixture-input".into(),
        initial_sha256: se_types::Sha256::from_bytes([0; 32]),
        initial_offered: false,
        session_create_attempted: false,
        policy_sha256: None,
        previous_policy_sha256: None,
        client_closed: None,
        resume_release: None,
        input_free_resume: false,
        notice: None,
        restart_key: None,
        restart_effect: None,
        restart_settled: false,
        restart_reply_sent: false,
        superseded_by_restart: false,
        bootstrap: None,
        service: None,
        retirement: None,
        registration: None,
        server_sha256: None,
        endpoint: None,
        identity: None,
        capability_repair: None,
    };
    Ok(Service::new(
        journal,
        Journal::path(&f.options.state_directory, &f.project, &f.a),
    ))
}

async fn wait_json(path: &Path, field: &str) -> Check<serde_json::Value> {
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && value[field].as_bool() == Some(true)
        {
            return Ok(value);
        }
        if tokio::time::Instant::now() >= until {
            return Err(format!("fixture did not publish {field}").into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct ServiceCleanup {
    profile: PathBuf,
    replacement: Option<std::process::Child>,
}
impl ServiceCleanup {
    fn finish(&mut self) -> Check {
        let Some(child) = &mut self.replacement else {
            return Ok(());
        };
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(
            self.profile.join("fixture-replacement.json"),
        )?)?;
        let endpoint = value["endpoint"]
            .as_str()
            .ok_or("replacement endpoint absent")?;
        server::post(endpoint, "/fixture/exit", &serde_json::json!({}))?;
        let until = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err("replacement fixture failed to exit cleanly".into());
                }
                self.replacement = None;
                return Ok(());
            }
            if std::time::Instant::now() >= until {
                return Err("replacement fixture remains live".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
impl Drop for ServiceCleanup {
    fn drop(&mut self) {
        for name in ["fixture-replacement.json", "fixture-registration.json"] {
            if let Ok(bytes) = std::fs::read(self.profile.join(name))
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && let Some(endpoint) = value["endpoint"].as_str()
            {
                let _ = server::post(endpoint, "/fixture/exit", &serde_json::json!({}));
            }
        }
        if let Some(child) = &mut self.replacement {
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while child.try_wait().is_ok_and(|status| status.is_none())
                && std::time::Instant::now() < until
            {
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

async fn register_fixture(
    coordinator: &LaunchCoordinator,
    f: &Fixture,
    session: se_types::SessionId,
    profile: &Path,
    executable: &Path,
    digest: se_types::Sha256,
    deadline: &Deadline,
) -> Check<(ServiceSlot, Arc<se_proc::OwnedProcess>)> {
    let mut service = service(f, session, profile)?;
    service.register_image(digest, false);
    service.persist(coordinator, deadline).await?;
    let invocation = se_proc::NativeExecutablePin::open(executable)?
        .ok_or("fixture image absent")?
        .prepare()?;
    let policy = se_proc::LaunchPolicy {
        containment: se_proc::ContainmentRequirement::BestAvailable,
        writes: se_proc::WritePolicy::NamedUnrestricted {
            profile: "fixture".into(),
        },
        network: se_proc::NetworkPolicy::Allow,
        hardening: se_proc::OptionalHardening::Off,
    };
    coordinator
        .start_secode_auxiliary(
            &mut service,
            Auxiliary::Service,
            invocation,
            vec![
                "--exact".into(),
                "process::secode::registered_rebind_test::fixture_child".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            f.home.clone(),
            policy,
            None,
            deadline,
        )
        .await?;
    let original = service
        .process()
        .cloned()
        .ok_or("native service custody absent")?;
    let slot = Arc::new(tokio::sync::Mutex::new(service));
    coordinator
        .secode_services
        .0
        .lock()
        .await
        .insert((f.project.clone(), f.a.clone()), slot.clone());
    Ok((slot, original))
}

async fn reject_wrong_image(f: &Fixture, executable: &Path) -> Check {
    let wrong_image = f
        .home
        .join(format!("wrong-image{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(executable, &wrong_image)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&wrong_image)?
        .write_all(b"fixture image mismatch")?;
    let mut wrong = std::process::Command::new(&wrong_image)
        .args([
            "--exact",
            "process::secode::registered_rebind_test::fixture_child",
            "--ignored",
            "--nocapture",
        ])
        .env("SE_REBIND_REJECT_HOME", &f.options.state_directory)
        .env("SE_REBIND_REJECT_PROJECT", f.project.to_string())
        .env("SE_REBIND_REJECT_AGENT", f.a.to_string())
        .spawn()?;
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = wrong.try_wait()? {
            if !status.success() {
                return Err("unregistered image refusal failed".into());
            }
            return Ok(());
        }
        if tokio::time::Instant::now() >= until {
            return Err("unregistered image probe timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[test]
fn registered_native_service_rebinds_and_releases_the_seat() -> Check {
    let initialized = crate::initialize_host_process()?;
    let mut f = Fixture::new()?;
    f._root = f._root.take().map(|root| root.until_success());
    seed(&f)?;
    let session = seed_session(&f)?;
    let profile = f.home.join("service-profile");
    private_profile(&profile)?;
    let mut cleanup = ServiceCleanup {
        profile: profile.clone(),
        replacement: None,
    };
    let executable = std::env::current_exe()?;
    let observed = se_proc::native_ipc::observe_ipc_self()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result: Check = rt.block_on(async {
        let mut options = support::options();
        options.timeout = Duration::from_secs(120);
        let deadline = Deadline::from_options(&options)?;
        let mut host = crate::HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &deadline).await?;
        host.configure(se_config::config_policy::ConfigFile::default())?;
        let (coordinator, reconciliation) = crate::LaunchCoordinator::install(&mut host, crate::ProcessOptions {
            helper_executable: NativePath::from_local(executable.clone())?, linux_delegation: se_proc::LinuxDelegation::CurrentScope,
            maximum_sessions: 4, restore_deadline_ms: 20_000, stop_grace_ms: None,
        }, &deadline).await?;
        assert!(reconciliation.unproved.is_empty());
        let listener = host.listen(rt.handle().clone(), &deadline).await?;
        let (slot, original) = register_fixture(&coordinator, &f, session.clone(), &profile,
            &executable, observed.image_sha256(), &deadline).await?;
        let stop = host.local_stop();
        let work = async {
            let result: Check = async {
                let registration_path = profile.join("fixture-registration.json");
                let until = tokio::time::Instant::now() + Duration::from_secs(30);
                let old = loop {
                    if let Ok(bytes) = std::fs::read(&registration_path)
                        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) { break value; }
                    if tokio::time::Instant::now() >= until { return Err("original service did not start".into()); }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                };
                let old_url = old["endpoint"].as_str().ok_or("old endpoint absent")?;
                reject_wrong_image(&f, &executable).await?;
                server::post(old_url, "/fixture/restart", &serde_json::json!({"home":f.options.state_directory,"project_id":f.project,"agent_id":f.a}))?;
                cleanup.replacement = Some(std::process::Command::new(&executable)
                    .args(["--exact", "process::secode::registered_rebind_test::fixture_child", "--ignored", "--nocapture"])
                    .env("SE_REBIND_PROFILE", &profile).spawn()?);
                let state_path = profile.join("fixture-state.json");
                wait_json(&state_path, "rebound").await?;
                let reader = present(SqliteFactory::open_reader(&f.options)?)?;
                for old_hash in [[11; 32], [12; 32]] {
                    assert!(matches!(reader.credential(old_hash)?, se_types::Read::Absent { .. }));
                }
                let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(profile.join("fixture-replacement.json"))?)?;
                let endpoint = saved["endpoint"].as_str().ok_or("replacement endpoint absent")?;
                {
                    let service = slot.lock().await;
                    let restart = service.restart().ok_or("rebind not registered")?;
                    assert_ne!(u64::from(restart.identity().pid.get()), old["pid"].as_u64().ok_or("old PID absent")?);
                    assert_eq!(restart.identity().image_sha256, observed.image_sha256());
                    assert!(restart.control().verify_restart(&deadline).await.is_err(), "not-ready challenge was accepted");
                }
                let state: serde_json::Value = serde_json::from_slice(&std::fs::read(&state_path)?)?;
                assert!(state["not_ready_count"].as_u64().is_some_and(|count| count > 0));
                server::post(endpoint, "/fixture/ready", &serde_json::json!({}))?;
                server::post(old_url, "/fixture/exit", &serde_json::json!({}))?;
                let until = tokio::time::Instant::now() + Duration::from_secs(20);
                loop {
                    if matches!(coordinator.native.witness_exit(&original).map_err(|error| format!("native exit witness: {error:?}"))?, se_proc::StopObservation::Complete(_)) { break; }
                    if tokio::time::Instant::now() >= until { return Err("original scope did not exit".into()); }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Ok(())
            }.await;
            stop.request();
            result
        };
        let (exit, result) = support::join(host.serve(listener), work).await;
        let report = exit.finish(&deadline).await;
        result?;
        assert!(report.pending.is_empty(), "shutdown remains pending: {:?}", report.pending);
        assert!(wait_json(&profile.join("fixture-state.json"), "released").await?["released"] == true);
        assert!(cleanup.replacement.as_mut().ok_or("replacement absent")?.try_wait()?.is_none(), "seat release stopped shared service");
        Ok(())
    });
    let cleanup_result = cleanup.finish();
    let result = result.and(cleanup_result);
    f._root
        .as_ref()
        .ok_or("fixture root absent")?
        .finish(result)
}
