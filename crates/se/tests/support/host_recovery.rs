use crate::*;
use std::io::{BufRead, Read as _};
use std::process::{Child, Command, Stdio};

pub(super) struct OwnedChild(pub(super) Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            // This retained std Child is the exact private fixture we spawned;
            // never find or terminate another process by a name or pattern.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn payload(f: &Fixture) -> Result<String, Box<dyn std::error::Error>> {
    Ok(serde_json::to_string(&(
        &f.home, &f.store, &f.owner, &f.project, &f.a, &f.b,
    ))?)
}
/// Protects: restart following an actual abrupt host process exit reconciles its protected stale endpoint under the exclusive lease and publishes a different live native owner.
pub fn restart_after_crash() -> Check {
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    let (direct, lease) = f.direct()?;
    drop(direct);
    drop(lease);
    let machine = route::identity::ensure_machine_identity(&f.options.state_directory)?;
    let credential = secret()?;
    publish(&f, "credential", credential.expose())?;
    let arguments = payload(&f)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--crash-sdk-child", &arguments])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for name in ["SE_SESSION", "CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI"] {
        command.env_remove(name);
    }
    let mut child = OwnedChild(command.spawn()?);
    let stdout = child.0.stdout.take().ok_or("private child stdout")?;
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout)
            .take(32768)
            .read_line(&mut line)
            .map(|_| line);
        let _ = sent.send(result);
    });
    let line = received.recv_timeout(Duration::from_secs(10))??;
    reader
        .join()
        .map_err(|_| "private readiness reader panicked")?;
    let (encoded, argv): (Vec<u8>, Vec<String>) = serde_json::from_str(&line)?;
    let endpoint = se_host::client::endpoint::decode_endpoint(&encoded)?;
    assert_eq!(argv.get(1).map(String::as_str), Some("--crash-sdk-child"));
    assert_eq!(argv.get(2), Some(&arguments));
    assert_eq!(endpoint.epoch.owner.fields().pid.get(), child.0.id());
    let observed = match se_proc::NativeProcessRuntime::read_process(
        machine.clone(),
        se_proc::ProcessId(child.0.id()),
    )
    .map_err(|error| format!("read exact owned crash child: {error:?}"))?
    {
        se_proc::ProcessRead::Present(value) => value,
        other => return Err(format!("private crash child is not natively live: {other:?}").into()),
    };
    assert_eq!(observed.identity.image, std::env::current_exe()?);
    let stale = std::fs::read(f.options.state_directory.join("endpoint.json"))?;
    child.0.kill()?;
    assert!(!child.0.wait()?.success());
    wait_native_exit(&observed.identity)?;
    assert_eq!(
        std::fs::read(f.options.state_directory.join("endpoint.json"))?,
        stale
    );
    let ready = host::start(
        &f.options.state_directory,
        &f.options.state_directory.join("config.toml"),
        machine,
        &bound()?,
    )
    .map_err(|error| format!("restart after actual crash with stale endpoint: {error:?}"))?;
    let _cleanup = ChildCleanup {
        endpoint: &ready.endpoint,
        identity: &ready.ready.identity,
        credential: &credential,
    };
    assert_ne!(ready.ready.identity, observed.identity);
    assert_ne!(ready.endpoint.epoch, endpoint.epoch);
    stop_native(&ready.endpoint, &credential, "recovered-crash-stop")?;
    wait_native_exit(&ready.ready.identity)?;
    assert!(
        !f.options
            .state_directory
            .join("endpoint.json")
            .try_exists()?
    );
    println!(
        "PASS crash_restart: exact owned child crashed, stale protected endpoint remained, and a new native owner restarted and retired it"
    );
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}

pub fn child(args: &[std::ffi::OsString]) -> Check {
    let (home, store, owner, project, a, b): (
        std::path::PathBuf,
        StoreId,
        se_types::HumanId,
        se_types::ProjectId,
        se_types::AgentId,
        se_types::AgentId,
    ) = serde_json::from_str(
        args.get(2)
            .and_then(|arg| arg.to_str())
            .ok_or("private fixture identities")?,
    )?;
    let f = std::mem::ManuallyDrop::new(Fixture {
        options: StoreOptions {
            state_directory: home.join("state"),
            busy_timeout: Duration::from_secs(2),
        },
        home,
        store,
        owner,
        project,
        a,
        b,
    });
    let machine =
        route::identity::require_machine(&route::files::Files::open(&f.options.state_directory)?)?;
    let initialized = se_host::initialize_host_process()?;
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    engine.block_on(async {
        let mut runtime = se_host::HostedRuntime::prepare(
            initialized,
            start_options(&f, epoch(machine)?)?,
            engine.handle().clone(),
            &bound()?,
        )
        .await?;
        let listener = runtime.listen(engine.handle().clone(), &bound()?).await?;
        let argv: Vec<_> = std::env::args().collect();
        println!(
            "{}",
            serde_json::to_string(&(
                se_host::client::endpoint::encode_endpoint(listener.endpoint())?.as_bytes(),
                argv
            ))?
        );
        std::io::stdout().flush()?;
        let _exit = runtime.serve(listener).await;
        Err::<(), Box<dyn std::error::Error>>(
            "crash fixture unexpectedly received graceful stop".into(),
        )
    })
}
