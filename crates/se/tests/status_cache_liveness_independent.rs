//! Hosted status retains display facts without retaining native health.
#![cfg(any(target_os = "linux", windows))]

use se_host::{
    EndpointRecord, IpcEnvelope, IpcRequest, RawOperation,
    client::{
        BlockingConnection, BlockingIpcClient, ClientOptions, endpoint::decode_endpoint,
        lease::ClientCredential,
    },
};
use serde_json::{Value, json};
use std::{
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Host {
    root: PathBuf,
    image: PathBuf,
    home: PathBuf,
    child: Option<Child>,
    finished: bool,
}

impl Host {
    fn command(&self) -> Command {
        let mut command = Command::new(&self.image);
        command.env_clear();
        for key in ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .arg("--home")
            .arg(&self.home)
            .current_dir(self.root.join("repo"))
            .env("HOME", self.root.join("owner"))
            .env("USERPROFILE", self.root.join("owner"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("TMPDIR", self.root.join("tmp"))
            .env("TEMP", self.root.join("tmp"))
            .env("TMP", self.root.join("tmp"));
        command
    }

    fn start() -> Check<(Self, EndpointRecord)> {
        se_proc::initialize_file_creation_owner()?;
        let secret = se_proc::random_secret().map_err(|e| format!("entropy: {e:?}"))?;
        let root =
            std::env::temp_dir().join(format!("sv-{}", se_types::hex_lower(&secret.expose()[..8])));
        drop(se_proc::NativeStateFiles::create(&root)?);
        for name in ["repo", "owner", "run", "tmp"] {
            drop(se_proc::NativeStateFiles::create(&root.join(name))?);
        }
        let image = root.join(if cfg!(windows) { "se.exe" } else { "se" });
        fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
        let mut host = Self {
            home: root.join("state"),
            root,
            image,
            child: None,
            finished: false,
        };
        let initialized = host
            .command()
            .args(["--json", "init", "--name", "Status Control"])
            .output()?;
        assert!(
            initialized.status.success(),
            "init: {} {}",
            String::from_utf8_lossy(&initialized.stdout),
            String::from_utf8_lossy(&initialized.stderr)
        );
        let log = fs::File::create(host.root.join("host.log"))?;
        host.child = Some(
            host.command()
                .args(["up", "--foreground", "--json"])
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(bytes) = fs::read(host.home.join("endpoint.json")) {
                let endpoint = decode_endpoint(&bytes)?;
                let child = host.child.as_mut().ok_or("child absent")?;
                assert_eq!(endpoint.epoch.owner.fields().pid.get(), child.id());
                host.verify_command()?;
                return Ok((host, endpoint));
            }
            if host
                .child
                .as_mut()
                .ok_or("child absent")?
                .try_wait()?
                .is_some()
                || Instant::now() >= deadline
            {
                return Err(format!(
                    "foreground host failed: {}",
                    fs::read_to_string(host.root.join("host.log"))?
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn verify_command(&self) -> Check {
        let pid = self.child.as_ref().ok_or("child absent")?.id();
        #[cfg(target_os = "linux")]
        let command = String::from_utf8(fs::read(format!("/proc/{pid}/cmdline"))?)?;
        #[cfg(windows)]
        let command = {
            let script = format!(
                "(Get-CimInstance Win32_Process -Filter 'ProcessId ={}').CommandLine",
                pid
            );
            let output = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()?;
            assert!(output.status.success(), "native command-line read failed");
            String::from_utf8(output.stdout)?
        };
        assert!(command.contains(self.home.to_str().ok_or("home encoding")?));
        assert!(command.contains("--foreground"));
        eprintln!("owned foreground command: {command:?}");
        Ok(())
    }

    fn kill_and_join(&mut self) -> Check {
        if self
            .child
            .as_mut()
            .ok_or("child absent")?
            .try_wait()?
            .is_none()
        {
            self.verify_command()?;
            let child = self.child.as_mut().ok_or("child absent")?;
            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }

    fn finish(mut self) -> Check {
        self.kill_and_join()?;
        let lease = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.home.join("runtime.lock"))?;
        lease.try_lock()?;
        drop(lease);
        fs::remove_dir_all(&self.root)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if self.child.is_some()
            && let Err(error) = self.kill_and_join()
        {
            eprintln!("owned host cleanup failed: {error}");
        }
        eprintln!("retained status fixture: {}", self.root.display());
    }
}

fn options(endpoint: &EndpointRecord) -> ClientOptions {
    ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}

fn connect(home: &Path, endpoint: &EndpointRecord) -> Check<BlockingConnection> {
    Ok(BlockingIpcClient::connect_authenticated(
        endpoint,
        ClientCredential::Machine(se_types::Secret::new(fs::read(home.join("credential"))?)?),
        NonZeroU32::new(1_048_576).ok_or("reply bound")?,
        &options(endpoint),
    )?)
}

fn status(client: &mut BlockingConnection, endpoint: &EndpointRecord, id: u64) -> Check<Value> {
    let response = client.exchange(
        IpcEnvelope {
            version: client.negotiated().version,
            request_id: id,
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
        &options(endpoint),
    )?;
    if response.schema != "se.status/v1" {
        return Err(format!("status refused: {}", response.value).into());
    }
    Ok(response.value)
}

fn prime(host: &Host, endpoint: &EndpointRecord) -> Check<BlockingConnection> {
    let mut client = connect(&host.home, endpoint)?;
    let first = status(&mut client, endpoint, 1)?;
    std::thread::sleep(Duration::from_millis(10));
    let second = status(&mut client, endpoint, 2)?;
    assert_eq!(first["runtime"]["state"], "running");
    assert_eq!(second["runtime"]["state"], "running");
    for field in ["pid", "exe", "machine_id"] {
        assert_eq!(
            first["runtime"]["process"][field],
            second["runtime"]["process"][field]
        );
    }
    assert!(second["runtime"]["process"]["started_at"].is_string());
    assert_eq!(
        second["runtime"]["process"]["pid"],
        endpoint.epoch.owner.fields().pid.get()
    );
    assert_ne!(
        first["runtime"]["observed_at"],
        second["runtime"]["observed_at"]
    );
    Ok(client)
}

#[test]
fn host_death_between_status_calls_never_returns_cached_health() -> Check {
    let (mut host, endpoint) = Host::start()?;
    let mut client = prime(&host, &endpoint)?;
    host.kill_and_join()?;
    assert!(status(&mut client, &endpoint, 3).is_err());
    let direct = host.command().args(["--json", "status"]).output()?;
    let value: Value = serde_json::from_slice(&direct.stdout)?;
    if direct.status.success() {
        assert_eq!(value["schema"], "se.status/v1");
        assert_ne!(value["runtime"]["state"], "running", "{value}");
    } else {
        assert_eq!(value["schema"], "se.error/v1");
        assert!(
            value["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
    }
    host.finish()
}

#[cfg(target_os = "linux")]
#[test]
fn image_identity_change_is_refused_after_display_was_cached() -> Check {
    let (host, endpoint) = Host::start()?;
    let mut client = prime(&host, &endpoint)?;
    let retired = host.root.join("retired-se");
    fs::rename(&host.image, &retired)?;
    let observed = se_proc::read_process(
        endpoint.epoch.owner.fields().machine.clone(),
        se_proc::ProcessId(endpoint.epoch.owner.fields().pid.get()),
    )
    .map_err(|error| format!("outside identity observation: {error:?}"))?;
    let se_proc::ProcessRead::Present(observed) = observed else {
        return Err("the renamed native host must remain live".into());
    };
    assert_eq!(observed.identity.image, retired);
    assert!(status(&mut client, &endpoint, 3).is_err());
    host.finish()
}
