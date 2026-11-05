#![allow(
    dead_code,
    reason = "The real native fixture is shared with store consumers."
)]
#[cfg(any(target_os = "linux", windows))]
use se_types::Read;
#[cfg(any(target_os = "linux", windows))]
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Output},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[cfg(any(target_os = "linux", windows))]
use std::io::Write;
#[cfg(any(target_os = "linux", windows))]
#[path = "support/runtime_host.rs"]
mod runtime_host;
#[cfg(any(target_os = "linux", windows))]
use runtime_host::RunningHost;
#[cfg(any(target_os = "linux", windows))]
static RUNTIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
/// Protects: uninstall itself verifies shutdown of an actual live host with empty process inventory, then removes installation bytes while retaining user work, history and credentials.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn uninstall_verifies_live_host_shutdown_before_removing_files() -> Check {
    let _serial = RUNTIME
        .lock()
        .map_err(|_| "runtime fixture mutex poisoned")?;
    se_proc::initialize_file_creation_owner()?;
    for json in [true, false] {
        uninstall_live_host(json)?;
    }
    Ok(())
}
#[cfg(any(target_os = "linux", windows))]
fn uninstall_live_host(json: bool) -> Check {
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let repo = f.home.join("repository");
    std::fs::create_dir(&repo)?;
    std::fs::write(repo.join("user-work.txt"), b"retained user work")?;
    let host_image = f.home.join(if cfg!(windows) {
        "host-se.exe"
    } else {
        "host-se"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &host_image)?;
    let binary = host_image.as_path();
    let initialized = checked(
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
    // Keep an independent CLI image for outside history readback and error cleanup.
    let host = RunningHost::start(binary, home)?;
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
    let store_id = store.info()?.id;
    drop(store);
    let retained = ["machine.json", "credential", "config.toml"]
        .map(|name| std::fs::read(home.join(name)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let project = initialized["profile"]["project"]
        .as_str()
        .ok_or("initialized project missing")?;
    let history = || {
        checked(
            command(binary, home, true)
                .args(["--project", project, "history", "--limit", "100"])
                .output()?,
        )
    };
    let before = history()?;
    let before_items = before["items"].as_array().ok_or("history items missing")?;
    assert!(!before_items.is_empty(), "fixture must retain real history");
    let output = terminal_uninstall(&installed, home, json)?;
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    #[cfg(target_os = "linux")]
    assert!(
        output.status.success(),
        "uninstall failed (json={json}, status={}, code={:?}): {printed}",
        output.status,
        output.status.code()
    );
    #[cfg(windows)]
    {
        assert_eq!(
            output.status.code(),
            Some(75),
            "direct Windows uninstall lost its deferred handoff: {printed}"
        );
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains("Finishing uninstall after this process exits (exit 75)")
                && diagnostic.contains("Completion is pending")
                && diagnostic.contains("uninstall.ps1"),
            "deferred exit lost its meaning or final-verdict alternative: {printed}"
        );
        // The installed parent must exit before Windows can remove its image.
        // Exit 75 only delegates: independently wait for every reported effect,
        // including the helper's own teardown, without performing cleanup here.
        let cleanup = se_proc::UninstallHelperCleanup::decode(&std::fs::read(
            home.join("uninstall-helper-cleanup.json"),
        )?)?;
        let mut paths = vec![installed.as_path(), record.as_path(), cleanup.path()];
        if let Some(directory) = cleanup.directory_path() {
            paths.push(directory);
        }
        wait_for_absence(&paths, std::time::Duration::from_secs(45))?;
    }
    assert!(
        !host.live()?,
        "successful uninstall left the exact host live"
    );
    assert!(
        !home.join("endpoint.json").try_exists()?,
        "stale endpoint after uninstall"
    );
    assert!(
        !installed.try_exists()?,
        "uninstall kept its installed image"
    );
    assert!(
        !record.try_exists()?,
        "uninstall kept its installation record"
    );
    // Windows stdout remains attached to the real human console. Linux's PTY
    // combines both streams, so inspect its terminal JSON without claiming a
    // separate machine-readable stdout witness.
    #[cfg(target_os = "linux")]
    if json {
        let outcome: serde_json::Value = printed
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line).ok())
            .ok_or_else(|| format!("missing actual uninstall JSON: {printed}"))?;
        assert_eq!(outcome["complete"], true, "uninstall incomplete: {outcome}");
    }
    for (name, bytes) in ["machine.json", "credential", "config.toml"]
        .into_iter()
        .zip(retained)
    {
        assert_eq!(
            std::fs::read(home.join(name))?,
            bytes,
            "uninstall changed retained {name}"
        );
    }
    assert_eq!(
        std::fs::read(repo.join("user-work.txt"))?,
        b"retained user work"
    );
    let after = history()?;
    let after_items = after["items"]
        .as_array()
        .ok_or("retained history items missing")?;
    // Verified shutdown may append events; every pre-existing public event must
    // still read back unchanged through the independent CLI after removal.
    for event in before_items {
        assert!(
            after_items.contains(event),
            "uninstall changed prior history: {event}"
        );
    }
    let outside = present(se_store::SqliteFactory::open_reader(&f.options)?)?;
    assert_eq!(
        outside.info()?.id,
        store_id,
        "uninstall replaced retained store"
    );
    drop(outside);
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
fn wait_for_absence(paths: &[&Path], timeout: std::time::Duration) -> Check {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut remaining = Vec::new();
        for path in paths {
            match std::fs::symlink_metadata(path) {
                Ok(_) => remaining.push(format!("{} (present)", path.display())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => {
                    remaining.push(format!("{} (unreadable: {error})", path.display()));
                }
            }
        }
        if remaining.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "uninstall completion not witnessed; remaining observations: {remaining:?}"
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Protects: a deferred exit cannot qualify completion while a reported helper
/// remains, even when the installed image and ownership record are absent.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn completion_wait_requires_every_reported_artifact_absent() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let image = f.home.join("absent-image");
    let record = f.home.join("absent-record");
    let helper = f.home.join("still-present-helper");
    std::fs::write(&helper, b"preserve until teardown")?;
    let paths = [image.as_path(), record.as_path(), helper.as_path()];
    let failure = match wait_for_absence(&paths, std::time::Duration::ZERO) {
        Err(error) => error,
        Ok(()) => return Err("remaining helper must refuse completion".into()),
    };
    assert!(failure.to_string().contains("still-present-helper"));
    assert_eq!(std::fs::read(&helper)?, b"preserve until teardown");
    std::fs::remove_file(&helper)?;
    wait_for_absence(&paths, std::time::Duration::ZERO)
}

#[cfg(target_os = "linux")]
fn terminal_uninstall(
    image: &Path,
    home: &Path,
    json: bool,
) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new("python3").arg("-c").arg(r#"
import os,pty,select,signal,subprocess,sys,time
image,home,json=sys.argv[1:]
env=os.environ.copy()
for key in ['SE_SESSION','SE_CONFIG','SE_PROJECT','SE_LOG','SE_HOME','CLAUDECODE','CODEX_THREAD_ID','CODEX_CI']:env.pop(key,None)
master,slave=pty.openpty()
args=[image]+(['--json'] if json=='true' else [])+['--home',home,'uninstall']
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
"#).arg(image).arg(home).arg(json.to_string()).output()?)
}

#[cfg(windows)]
fn terminal_uninstall(
    image: &Path,
    home: &Path,
    json: bool,
) -> Result<Output, Box<dyn std::error::Error>> {
    let root = home.parent().ok_or("fixture root missing")?;
    let script = root.join("runtime-console.ps1");
    std::fs::write(&script, include_str!("support/runtime_console.ps1"))?;
    let powershell = se_proc::windows_directory()
        .map_err(|error| format!("native Windows directory: {error:?}"))?
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut run = Command::new(powershell);
    for name in [
        "SE_SESSION",
        "SE_CONFIG",
        "SE_PROJECT",
        "SE_LOG",
        "SE_HOME",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        run.env_remove(name);
    }
    let literal = |path: &Path| -> Result<String, Box<dyn std::error::Error>> {
        Ok(format!(
            "'{}'",
            path.to_str()
                .ok_or("console path encoding")?
                .replace('\'', "''")
        ))
    };
    let invocation = format!(
        "& ([ScriptBlock]::Create([IO.File]::ReadAllText({script}))) -Image {image} -HomePath {home} -Mode {mode} -ScriptPath {script}",
        script = literal(&script)?,
        image = literal(image)?,
        home = literal(home)?,
        mode = if json { "json" } else { "human" },
    );
    Ok(run
        .args(["-NoProfile", "-NonInteractive", "-Command", &invocation])
        .output()?)
}

/// Protects: F3 on both native platforms — init while a real host holds the writer lease names down/init, preserves identities and history, then the same requested project initializes after graceful down.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn live_host_init_refuses_with_down_then_retry_succeeds() -> Check {
    use se_store::{ReadStore, StoreFactory};
    let _serial = RUNTIME
        .lock()
        .map_err(|_| "runtime fixture mutex poisoned")?;
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let image = f
        .home
        .join(if cfg!(windows) { "f3-se.exe" } else { "f3-se" });
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let first = f.home.join("original project");
    let second = f.home.join("requested project");
    std::fs::create_dir(&first)?;
    std::fs::create_dir(&second)?;
    let initialized = checked(
        command(&image, home, true)
            .arg("init")
            .arg("--repo")
            .arg(&first)
            .args(["--name", "before-host"])
            .output()?,
    )?;
    let host = RunningHost::start(&image, home)?;
    let retained = ["machine.json", "credential", "endpoint.json"]
        .map(|name| std::fs::read(home.join(name)).map(|bytes| (name, bytes)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let reader = present(se_store::SqliteFactory::open_reader(&f.options)?)?;
    let before = reader.info()?;
    for json in [true, false] {
        let output = command(&image, home, json)
            .arg("init")
            .arg("--repo")
            .arg(&second)
            .args(["--name", "after-host"])
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains("error[state-conflict]"),
            "wrong F3 refusal: {diagnostic}"
        );
        assert!(
            diagnostic.contains("se down") && diagnostic.contains("se init"),
            "missing F3 down/init alternative: {diagnostic}"
        );
        if json {
            assert_eq!(value(&output)?["code"], "state-conflict");
        } else {
            assert!(output.stdout.is_empty());
        }
        assert!(host.live()?, "refused init displaced the exact live host");
        assert_eq!(
            reader.info()?.head,
            before.head,
            "refused init wrote durable events"
        );
        for (name, bytes) in &retained {
            assert_eq!(
                std::fs::read(home.join(name))?,
                *bytes,
                "refused init changed {name}"
            );
        }
        assert_eq!(
            std::fs::read_dir(&second)?.count(),
            0,
            "refused init changed the repository"
        );
    }
    // Exercise the documented recovery through the real CLI. The fixture's
    // direct IPC stop has a five-second budget and must cold-prove this much
    // larger test executable; it is not the owner's ordinary `se down` path.
    let stopped = checked(command(&image, home, true).arg("down").output()?)?;
    assert_eq!(stopped["complete"], true);
    assert!(!host.live()?, "public down retained the exact live host");
    let retried = checked(
        command(&image, home, true)
            .arg("init")
            .arg("--repo")
            .arg(&second)
            .args(["--name", "after-host"])
            .output()?,
    )?;
    assert_ne!(retried["project"]["id"], initialized["project"]["id"]);
    assert_eq!(retried["project"]["name"], "after-host");
    assert_ne!(
        reader.info()?.head,
        before.head,
        "legal init retry did not write the new project"
    );
    assert!(home.join("state.db").try_exists()?);
    Ok(())
}
