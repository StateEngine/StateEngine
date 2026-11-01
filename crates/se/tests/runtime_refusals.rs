#![allow(
    dead_code,
    reason = "The real native fixture is shared with store consumers."
)]
#[cfg(target_os = "linux")]
use se_types::{Read, Secret};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Output},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[cfg(target_os = "linux")]
use std::io::Write;

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
        "SE_LOG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    command
}
fn value(output: &Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "CLI JSON {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?)
}
fn checked(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "CLI fixture failed: {}; {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    value(&output)
}
fn options() -> se_host::client::ClientOptions {
    se_host::client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}

/// Protects: before initialization, a real ordinary command names setup-required and a se init remedy for the resolved home; absence does not become source-unreadable or create state implicitly.
#[test]
fn pre_init_command_names_setup_and_resolved_home() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    for json in [true, false] {
        let output = command(Path::new(env!("CARGO_BIN_EXE_se")), home, json)
            .arg("working-state")
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "pre-init command wrong refusal: {}; {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            (diagnostic.contains("se init")
                || (diagnostic.contains("se --home") && diagnostic.contains(" init"))),
            "missing legal setup alternative: {diagnostic}"
        );
        assert!(
            diagnostic.contains(home.to_str().ok_or("fixture home UTF8")?),
            "init remedy lost resolved home: {diagnostic}"
        );
        if json {
            let output = value(&output)?;
            assert_eq!(
                output["code"], "setup-required",
                "wrong absent-store result: {output}"
            );
        } else {
            assert!(diagnostic.contains("error[setup-required]"));
        }
        for name in ["state.db", "machine.json", "credential", "endpoint.json"] {
            assert!(
                !home.join(name).try_exists()?,
                "pre-init read created {name}"
            );
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
struct RunningHost {
    endpoint: se_host::EndpointRecord,
    key: Secret,
    identity: se_proc::ProcessIdentity,
}
#[cfg(target_os = "linux")]
impl RunningHost {
    fn stop(&self) -> Check {
        let until = se_types::UnixMicros::new(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_micros()
                + 5_000_000) as u64,
        )?;
        se_host::client::BlockingIpcClient::stop(
            &self.endpoint,
            &self.key,
            se_types::IdempotencyKey::new("runtime-refusal-cleanup")?,
            until,
            &options(),
        )?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.live()? {
            if std::time::Instant::now() >= deadline {
                return Err("exact fixture host did not exit after graceful stop".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    fn live(&self) -> Result<bool, Box<dyn std::error::Error>> {
        match se_proc::NativeProcessRuntime::read_process(
            self.identity.machine.clone(),
            self.identity.pid,
        )
        .map_err(|error| format!("outside native host observation: {error:?}"))?
        {
            se_proc::ProcessRead::Present(value) => Ok(value.identity == self.identity
                && !matches!(
                    value.state,
                    se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                )),
            se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. } => {
                Ok(false)
            }
        }
    }
}
#[cfg(target_os = "linux")]
impl Drop for RunningHost {
    fn drop(&mut self) {
        if matches!(self.live(), Ok(true)) {
            let _ = self.stop();
        }
    }
}

/// Protects: uninstall checks a real live host even when the protected process inventory is empty; it either proves graceful host exit first or preserves the installation and names se down.
#[cfg(target_os = "linux")]
#[test]
fn uninstall_stops_or_refuses_the_actual_live_host() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let repo = f.home.join("repository");
    std::fs::create_dir(&repo)?;
    let binary = Path::new(env!("CARGO_BIN_EXE_se"));
    checked(
        command(binary, home, true)
            .arg("init")
            .arg("--repo")
            .arg(&repo)
            .args(["--name", "runtime-refusal"])
            .output()?,
    )?;
    let installed = f.home.join(if cfg!(windows) {
        "installed-se.exe"
    } else {
        "installed-se"
    });
    std::fs::copy(binary, &installed)?;
    let native_owner = se_proc::observe_owner_self(&[])?;
    let owner = match native_owner.owner() {
        se_proc::NativeOwner::Unix {
            real_uid,
            effective_uid,
        } => {
            assert_eq!(real_uid, effective_uid);
            effective_uid.to_string()
        }
        se_proc::NativeOwner::Windows { sid } => sid.clone(),
    };
    let manifest = serde_json::to_vec(
        &serde_json::json!({"schema":"stateengine-install/v1", "owner":owner, "files":[{"path":installed,"sha256":format!("{:x}", Sha256::digest(std::fs::read(&installed)?))}], "created_directories":[], "path_edits":[]}),
    )?;
    let files = se_proc::NativeStateFiles::open(home)?;
    let mut stage = files.create_staging(home)?;
    stage.file.write_all(&manifest)?;
    stage.file.sync_all()?;
    drop(stage.file);
    let record = home.join("standalone-install.json");
    files.publish_no_replace(&stage.path, &record)?;
    // Keep the host's real executable available for graceful cleanup even if
    // the faulty uninstall deletes the separate, byte-identical installed copy.
    checked(command(binary, home, true).arg("up").output()?)?;
    let endpoint =
        se_host::client::endpoint::decode_endpoint(&std::fs::read(home.join("endpoint.json"))?)?;
    let identity = match se_proc::NativeProcessRuntime::read_process(
        endpoint.epoch.owner.fields().machine.clone(),
        se_proc::ProcessId(endpoint.epoch.owner.fields().pid.get()),
    )
    .map_err(|error| format!("read native host: {error:?}"))?
    {
        se_proc::ProcessRead::Present(value) => value.identity,
        other => return Err(format!("fixture host is not live: {other:?}").into()),
    };
    let host = RunningHost {
        endpoint,
        key: Secret::new(std::fs::read(home.join("credential"))?)?,
        identity,
    };
    assert!(host.live()?);
    let store = match se_store::SqliteFactory::open_reader(&f.options)? {
        Read::Present { value } => value,
        _ => return Err("initialized fixture reader missing".into()),
    };
    use se_store::{ReadStore, StoreFactory};
    let inventory = store.owner_guard(
        &fixture::Files(se_proc::NativeStateFiles::open(home)?),
        budget(1000, 2 * 1024 * 1024, None)?,
    )?;
    assert!(
        !inventory.has_process_records,
        "test must exercise the real empty-inventory gap"
    );
    drop(store);
    let output = terminal_uninstall(&installed, home)?;
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome: serde_json::Value = printed
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .ok_or_else(|| format!("missing actual uninstall JSON: {printed}"))?;
    let remained_live = host.live()?;
    if remained_live {
        host.stop()?;
        assert!(
            !output.status.success(),
            "uninstall claimed success while its native host remained live: {outcome}"
        );
        assert!(
            (printed.contains("se down")
                || (printed.contains("se --home") && printed.contains(" down"))),
            "live-host refusal omitted graceful down alternative: {outcome}"
        );
        assert!(
            installed.try_exists()?,
            "uninstall removed its image with a live host"
        );
        assert_eq!(
            std::fs::read(&record)?,
            manifest,
            "uninstall changed its installation record while the host stayed live"
        );
    } else {
        assert!(
            !home.join("endpoint.json").try_exists()?,
            "graceful uninstall left its endpoint published"
        );
    }
    assert!(
        home.join("state.db").try_exists()?,
        "uninstall removed retained user history"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn terminal_uninstall(image: &Path, home: &Path) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new("python3").arg("-c").arg(r#"
import os,pty,select,signal,subprocess,sys,time
image,home=sys.argv[1:]
env=os.environ.copy()
for key in ['SE_SESSION','SE_CONFIG','SE_PROJECT','SE_LOG','SE_HOME','CLAUDECODE','CODEX_THREAD_ID','CODEX_CI']:env.pop(key,None)
master,slave=pty.openpty()
args=[image,'--json','--home',home,'uninstall']
child=subprocess.Popen(args,stdin=slave,stdout=slave,stderr=slave,env=env,start_new_session=True)
os.close(slave)
deadline=time.monotonic()+30
data=bytearray()
while time.monotonic()<deadline:
    if select.select([master],[],[],.1)[0]:
        try:part=os.read(master,4096)
        except OSError:break
        if not part:break
        data.extend(part)
        if len(data)>262144:raise RuntimeError('uninstall output exceeded fixture budget')
    if child.poll() is not None:break
else:
    actual=open('/proc/'+str(child.pid)+'/cmdline','rb').read().split(b'\0')[:-1]
    if actual!=[os.fsencode(value) for value in args]:raise RuntimeError('owned uninstall child identity changed; refusing signal')
    os.kill(child.pid,signal.SIGKILL);child.wait()
    raise RuntimeError('exact uninstall child exceeded deadline')
os.close(master)
sys.stdout.buffer.write(data)
sys.exit(child.wait(timeout=3))
"#).arg(image).arg(home).output()?)
}
