//! Public CLI success and honest refusal from actual strict Windows jobs.
#![cfg(windows)]
use std::{
    error::Error,
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
fn clear(command: &mut Command) {
    for key in [
        "SE_HOME",
        "SE_CONFIG",
        "SE_PROJECT",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(key);
    }
}
struct Fixture {
    root: PathBuf,
    executable: PathBuf,
    home: PathBuf,
    host: Option<se_proc::ProcessIdentity>,
}
impl Fixture {
    fn new(case: &str) -> Result<Self> {
        se_proc::initialize_file_creation_owner()?;
        let root = std::env::temp_dir().join(format!(
            "se-job-{case}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        drop(se_proc::NativeStateFiles::create(&root)?);
        // Cargo hard-links its binary; the installed runtime requires a single-link image.
        let executable = root.join("se.exe");
        fs::copy(env!("CARGO_BIN_EXE_se"), &executable)?;
        let mut fixture = Self {
            home: root.join("state"),
            root,
            executable,
            host: None,
        };
        fs::create_dir(fixture.root.join("repo"))?;
        fixture.ok(&[
            "init",
            "--repo",
            fixture
                .root
                .join("repo")
                .to_str()
                .ok_or("non-UTF8 fixture")?,
        ])?;
        fs::write(
            fixture.root.join("strict-job.ps1"),
            include_str!("support/strict_job.ps1"),
        )?;
        // Keep the guard active even if a later assertion or native read fails.
        fixture.host = fixture.read_host()?;
        Ok(fixture)
    }
    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        clear(&mut command);
        command
            .arg("--home")
            .arg(&self.home)
            .arg("--json")
            .current_dir(&self.root);
        command
    }
    fn ok(&self, args: &[&str]) -> Result<serde_json::Value> {
        let output = self.command().args(args).output()?;
        assert!(
            output.status.success(),
            "public CLI failed; retained {}: {output:?}",
            self.root.display()
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    }
    fn read_host(&self) -> Result<Option<se_proc::ProcessIdentity>> {
        let path = self.home.join("endpoint.json");
        if !path.try_exists()? {
            return Ok(None);
        }
        let endpoint = se_host::client::endpoint::decode_endpoint(&fs::read(path)?)?;
        let fields = endpoint.epoch.owner.fields();
        let observed = se_proc::NativeProcessRuntime::read_process(
            fields.machine.clone(),
            se_proc::ProcessId(fields.pid.get()),
        )
        .map_err(|e| format!("outside exact runtime read: {e:?}"))?;
        let se_proc::ProcessRead::Present(live) = observed else {
            return Err("published host is not live".into());
        };
        assert_eq!(
            fs::canonicalize(&live.identity.image)?,
            fs::canonicalize(&self.executable)?
        );
        let se_types::StartIdentity::Windows { creation_filetime } = &fields.started else {
            return Err("endpoint does not carry a Windows process birth".into());
        };
        assert_eq!(
            live.identity.start,
            se_proc::StartIdentity::Windows {
                creation_filetime: creation_filetime.get()
            }
        );
        Ok(Some(live.identity))
    }
    fn run_strict(&mut self, refuse: bool) -> Result {
        let powershell = se_proc::windows_directory()
            .map_err(|e| format!("native Windows directory: {e:?}"))?
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut command = Command::new(powershell);
        clear(&mut command);
        command
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(self.root.join("strict-job.ps1"))
            .arg("-Se")
            .arg(&self.executable)
            .arg("-HomePath")
            .arg(&self.home)
            .arg("-Out")
            .arg(&self.root);
        if refuse {
            command.arg("-NoEligibleBroker");
        }
        let output = command.output()?;
        // This outside reader runs only after the strict-job shell has exited.
        self.host = self.read_host()?;
        assert!(
            output.status.success(),
            "strict-job fixture failed; retained {}: {output:?}",
            self.root.display()
        );
        let witness: serde_json::Value =
            serde_json::from_slice(&fs::read(self.root.join("job.json"))?)?;
        assert_eq!(witness["caller_in_job_before"], true);
        assert_eq!(witness["caller_in_job_after"], true);
        assert_eq!(witness["privilege_removed"], refuse);
        assert_eq!(witness["restricting_sids"], false);
        Ok(())
    }
    fn result(&self, mode: &str) -> Result<(String, Vec<u8>, String)> {
        Ok((
            fs::read_to_string(self.root.join(format!("{mode}.exit")))?
                .trim()
                .into(),
            fs::read(self.root.join(format!("{mode}.stdout")))?,
            fs::read_to_string(self.root.join(format!("{mode}.stderr")))?,
        ))
    }
    fn exited(&self, identity: &se_proc::ProcessIdentity) -> Result<bool> {
        match se_proc::NativeProcessRuntime::read_process(identity.machine.clone(), identity.pid)
            .map_err(|e| format!("outside runtime closure: {e:?}"))?
        {
            se_proc::ProcessRead::Absent { .. } => Ok(true),
            se_proc::ProcessRead::ExitedRecord {
                pid, boot, start, ..
            } if pid == identity.pid && boot == identity.boot && start == identity.start => {
                Ok(true)
            }
            se_proc::ProcessRead::Present(live) if live.identity == *identity => {
                Ok(live.state == se_proc::NativeState::ExitedAwaitingReap)
            }
            _ => Err("runtime identity changed; refusing another process".into()),
        }
    }
    fn stop(&mut self) -> Result {
        // Public down resolves only this fresh protected home's owned endpoint.
        // It also cleans a host when a preceding assertion failed before identity capture.
        if self.home.join("endpoint.json").try_exists()? {
            let output: Output = self.command().arg("down").output()?;
            if !matches!(output.status.code(), Some(0) | Some(2)) {
                return Err(format!(
                    "public down failed; retained {}: {output:?}",
                    self.root.display()
                )
                .into());
            }
        }
        if let Some(identity) = &self.host {
            let until = Instant::now() + Duration::from_secs(15);
            while !self.exited(identity)? {
                if Instant::now() >= until {
                    return Err("exact broker runtime did not exit".into());
                }
                std::thread::park_timeout(Duration::from_millis(10));
            }
        }
        if self.home.join("endpoint.json").try_exists()? {
            return Err("endpoint survived public shutdown".into());
        }
        let path = self.home.join("runtime.lock");
        if path.try_exists()? {
            let lease = fs::OpenOptions::new().read(true).write(true).open(path)?;
            lease.try_lock()?;
        }
        self.host = None;
        Ok(())
    }
    fn finish(mut self) -> Result {
        self.stop()?;
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists()
            && let Err(error) = self.stop()
        {
            eprintln!(
                "retaining owned strict-job fixture {}: {error}",
                self.root.display()
            );
        }
    }
}

#[test]
fn eligible_broker_runtime_outlives_strict_job_and_public_down_closes_it() -> Result {
    let mut f = Fixture::new("broker")?;
    f.run_strict(false)?;
    let identity = f
        .host
        .as_ref()
        .ok_or("eligible broker did not retain a live host after job exit")?;
    for mode in ["json", "plain"] {
        let (exit, stdout, stderr) = f.result(mode)?;
        assert_eq!(exit, "0", "broker launch refused: {stderr}");
        if mode == "json" {
            let value: serde_json::Value = serde_json::from_slice(&stdout)?;
            assert_eq!(value["state"], "running");
            assert_eq!(value["process"]["pid"], identity.pid.0);
        } else {
            let text = String::from_utf8(stdout)?;
            assert!(
                text.contains("Runtime running")
                    && text.contains(&format!("PID {}", identity.pid.0)),
                "wrong human startup output: {text}"
            );
        }
    }
    let witness: serde_json::Value = serde_json::from_slice(&fs::read(f.root.join("job.json"))?)?;
    assert_eq!(witness["runtime_outside_all_jobs"], true);
    assert_eq!(witness["runtime_pid"], identity.pid.0);
    let birth = witness["runtime_creation_filetime"]
        .as_str()
        .ok_or("missing outside native process birth")?
        .parse::<u64>()?;
    assert_eq!(
        identity.start,
        se_proc::StartIdentity::Windows {
            creation_filetime: birth
        }
    );
    let status = f.ok(&["status"])?;
    assert_eq!(status["runtime"]["state"], "running");
    assert_eq!(status["runtime"]["process"]["pid"], identity.pid.0);
    f.stop()?;
    println!(
        "PASS broker: JSON/plain CLI success; caller stayed in strict job; exact runtime outside all jobs survived job exit; public down closed it"
    );
    f.finish()
}

#[test]
fn no_eligible_broker_reports_named_refusal_and_current_legal_alternatives() -> Result {
    let mut f = Fixture::new("no-broker")?;
    f.run_strict(true)?;
    assert!(
        f.host.is_none(),
        "rights-mismatched caller published a host"
    );
    for mode in ["json", "plain"] {
        let (exit, stdout, stderr) = f.result(mode)?;
        assert_eq!(exit, "1", "refusal must use Refused exit status");
        assert!(
            stderr.contains("job-breakaway-refused") && stderr.contains("caller process PID"),
            "lost native refusal: {stderr}"
        );
        assert!(
            stderr.contains("directly from Start") && stderr.contains("this Windows account"),
            "lost current legal alternative: {stderr}"
        );
        assert!(
            !stderr.contains("restore access"),
            "native refusal misreported as storage"
        );
        if mode == "json" {
            let value: serde_json::Value = serde_json::from_slice(&stdout)?;
            assert_eq!(value["code"], "job-breakaway-refused");
            assert_eq!(value["exit"], 1);
            assert!(
                value["remedy"]["text"]
                    .as_str()
                    .ok_or("missing remedy")?
                    .contains("directly from Start")
            );
        } else {
            assert!(stdout.is_empty(), "human refusal contaminated stdout");
        }
        println!(
            "PASS {mode}: actual strict job and removed caller privilege; named refusal, current legal alternative, no host"
        );
    }
    f.finish()
}
