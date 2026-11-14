//! Public CLI failure/recovery controls with native-call barriers, never a host double.
#![cfg(target_os = "macos")]
use se_proc::{NativeProcessApi, NativeProcessRuntime, ProcessIdentity, ProcessRead};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn require(ok: bool, reason: &str) -> Check {
    if ok { Ok(()) } else { Err(reason.into()) }
}
struct Cli {
    child: Child,
    image: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
}
impl Cli {
    fn command_line(&self) -> Check<String> {
        let output = Command::new("/bin/ps")
            .args(["-p", &self.child.id().to_string(), "-o", "command="])
            .output()?;
        require(
            output.status.success(),
            "owned CLI command line is unreadable",
        )?;
        let text = String::from_utf8(output.stdout)?;
        require(
            text.contains(self.image.to_str().ok_or("fixture image is not UTF-8")?),
            "owned CLI command line differs from its private image",
        )?;
        Ok(text)
    }
    fn kill_join(&mut self) -> Check {
        let _ = self.command_line()?;
        self.child.kill()?;
        require(!self.child.wait()?.success(), "killed CLI reported success")
    }
    fn wait(&mut self) -> Check<(ExitStatus, Value)> {
        let until = Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = self.child.try_wait()? {
                let raw = fs::read(&self.stdout)?;
                let value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                if !status.success() {
                    eprintln!(
                        "CLI refusal: {} {}",
                        String::from_utf8_lossy(&raw),
                        fs::read_to_string(&self.stderr)?
                    );
                }
                return Ok((status, value));
            }
            require(
                Instant::now() < until,
                "owned public CLI exceeded its finite deadline",
            )?;
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Cli {
    fn drop(&mut self) {
        if self.child.try_wait().is_ok_and(|value| value.is_none()) {
            if let Err(error) = self.kill_join() {
                eprintln!("exact CLI cleanup remains unproved: {error}");
            }
        }
    }
}
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    repository: PathBuf,
    image: PathBuf,
    shim: PathBuf,
}
impl Fixture {
    fn new() -> Check<Self> {
        se_proc::initialize_file_creation_owner()?;
        let secret = se_proc::random_secret().map_err(|e| format!("native entropy: {e:?}"))?;
        let root = std::env::temp_dir().join(format!(
            "se-bs-{}",
            se_types::hex_lower(&secret.expose()[..8])
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let root = fs::canonicalize(root)?;
        let image = root.join("se");
        fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700))?;
        let repository = root.join("repo");
        fs::create_dir(&repository)?;
        fs::write(repository.join("user.txt"), b"Preserve user work.\n")?;
        let shim = root.join("barrier.dylib");
        let built = Command::new("cc")
            .args(["-dynamiclib", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&shim)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/bootstrap_review/barrier.c"
            ))
            .output()?;
        require(
            built.status.success(),
            &format!(
                "native barrier build: {}",
                String::from_utf8_lossy(&built.stderr)
            ),
        )?;
        let value = Self {
            home: root.join("home"),
            root,
            repository,
            image,
            shim,
        };
        let repo = value
            .repository
            .to_str()
            .ok_or("repository path is not UTF-8")?;
        value.checked(
            "init",
            &["init", "--repo", repo, "--name", "startup-review"],
        )?;
        Ok(value)
    }
    fn launch(&self, label: &str, arguments: &[&str], phase: Option<&str>) -> Check<Cli> {
        let stdout = self.root.join(format!("{label}.stdout"));
        let stderr = self.root.join(format!("{label}.stderr"));
        let mut command = Command::new(&self.image);
        command
            .args(["--json", "--no-color", "--home"])
            .arg(&self.home)
            .args(arguments)
            .current_dir(&self.repository)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &self.root)
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout)?)
            .stderr(fs::File::create(&stderr)?);
        if let Some(phase) = phase {
            command
                .env("DYLD_INSERT_LIBRARIES", &self.shim)
                .env("SE_REVIEW_BARRIER", &self.root)
                .env("SE_REVIEW_PHASE", phase);
        }
        Ok(Cli {
            child: command.spawn()?,
            image: self.image.clone(),
            stdout,
            stderr,
        })
    }
    fn checked(&self, label: &str, args: &[&str]) -> Check<Value> {
        let (status, value) = self.launch(label, args, None)?.wait()?;
        require(
            status.success(),
            "public command refused; raw output is retained",
        )?;
        Ok(value)
    }
    fn entered(&self, cli: &mut Cli) -> Check<u32> {
        let until = Instant::now() + Duration::from_secs(12);
        loop {
            if let Ok(text) = fs::read_to_string(self.root.join("entered")) {
                let _ = cli.command_line()?;
                return Ok(text.trim().parse()?);
            }
            if cli.child.try_wait()?.is_some() {
                return Err(format!(
                    "CLI exited before native barrier: {} {}",
                    fs::read_to_string(&cli.stdout)?,
                    fs::read_to_string(&cli.stderr)?
                )
                .into());
            }
            require(
                Instant::now() < until,
                "native startup barrier was not reached",
            )?;
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn identity(&self, pid: u32) -> Check<ProcessIdentity> {
        let observed = NativeProcessRuntime::read_process(
            se_types::MachineId::new("startup-review-native-observation")?,
            se_proc::ProcessId(pid),
        )
        .map_err(|e| format!("outside native process read: {e:?}"))?;
        let ProcessRead::Present(observed) = observed else {
            return Err(format!("fixture process is not live: {observed:?}").into());
        };
        require(
            fs::canonicalize(&observed.identity.image)? == fs::canonicalize(&self.image)?,
            "native process does not use this fixture image",
        )?;
        let command = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()?;
        require(
            command.status.success()
                && String::from_utf8_lossy(&command.stdout)
                    .contains(self.image.to_str().ok_or("image path is not UTF-8")?),
            "native full argv differs",
        )?;
        Ok(observed.identity)
    }
    fn host(&self) -> Check<ProcessIdentity> {
        let endpoint = se_host::client::endpoint::decode_endpoint(&fs::read(
            self.home.join("endpoint.json"),
        )?)?;
        self.identity(endpoint.epoch.owner.fields().pid.get())
    }
    fn closed(&self, expected: &ProcessIdentity) -> Check {
        let until = Instant::now() + Duration::from_secs(12);
        loop {
            let observed =
                NativeProcessRuntime::read_process(expected.machine.clone(), expected.pid)
                    .map_err(|e| format!("outside native exit read: {e:?}"))?;
            match observed {
                ProcessRead::Absent { .. } => return Ok(()),
                ProcessRead::ExitedRecord {
                    pid, boot, start, ..
                } if pid == expected.pid && boot == expected.boot && start == expected.start => {
                    return Ok(());
                }
                ProcessRead::Present(value) if value.identity == *expected => (),
                other => {
                    return Err(
                        format!("process identity changed while awaiting exit: {other:?}").into(),
                    );
                }
            }
            require(
                Instant::now() < until,
                "exact native fixture process did not exit",
            )?;
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn stop(&self, label: &str) -> Check {
        let host = self.host()?;
        let stopped = self.checked(label, &["down"])?;
        require(
            stopped["complete"] == true,
            "public down lacks a complete stop witness",
        )?;
        self.closed(&host)?;
        require(
            !self.home.join("endpoint.json").exists(),
            "endpoint survived witnessed stop",
        )?;
        require(
            fs::read(self.repository.join("user.txt"))? == b"Preserve user work.\n",
            "user work changed",
        )
    }
    fn only_host(&self, expected: &ProcessIdentity) -> Check {
        let output = Command::new("/bin/ps")
            .args(["-axo", "pid=,command="])
            .output()?;
        require(
            output.status.success(),
            "outside private-image census failed",
        )?;
        let selected = self.image.to_str().ok_or("image path is not UTF-8")?;
        let mut actual = vec![];
        for line in String::from_utf8(output.stdout)?
            .lines()
            .filter(|line| line.contains(selected))
        {
            let pid: u32 = line
                .split_whitespace()
                .next()
                .ok_or("census PID absent")?
                .parse()?;
            actual.push(self.identity(pid)?.pid.0);
        }
        require(
            actual == vec![expected.pid.0],
            "concurrent start left duplicate private-image processes",
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.home.join("endpoint.json").exists() {
            if let Err(error) = self.checked("finally-down", &["down"]) {
                eprintln!(
                    "fixture cleanup retained at {}: {error}",
                    self.root.display()
                );
            }
        }
    }
}

fn killed_start(phase: &str) -> Check {
    let f = Fixture::new()?;
    let mut cli = f.launch("interrupted-up", &["up"], Some(phase))?;
    let pid = f.entered(&mut cli)?;
    let host = if phase == "commit" {
        f.host()?
    } else {
        f.identity(pid)?
    };
    cli.kill_join()?;
    f.closed(&host)?;
    f.checked("recover-up", &["up"])?;
    let recovered = f.host()?;
    require(
        recovered != host,
        "restart reused the interrupted native process",
    )?;
    f.only_host(&recovered)?;
    f.stop("recover-down")
}
#[test]
fn killed_starting_cli_before_plan_transfer_releases_its_native_child() -> Check {
    killed_start("spawn")
}
#[test]
fn killed_starting_cli_before_commit_closes_the_unadmitted_host() -> Check {
    killed_start("commit")
}
#[test]
fn concurrent_start_retains_one_owner_and_both_callers_finish() -> Check {
    let f = Fixture::new()?;
    let mut first = f.launch("first-up", &["up"], Some("commit"))?;
    f.entered(&mut first)?;
    let expected = f.host()?;
    let mut second = f.launch("second-up", &["up"], None)?;
    let _ = second.command_line()?;
    std::thread::sleep(Duration::from_millis(200));
    fs::write(f.root.join("release"), b"release this exact fixture\n")?;
    let a = first.wait()?;
    let b = second.wait()?;
    require(
        a.0.success() || b.0.success(),
        "both concurrent starts failed",
    )?;
    require(
        f.host()? == expected,
        "concurrent start replaced the retained ready owner",
    )?;
    f.only_host(&expected)?;
    f.stop("concurrent-down")
}
#[test]
fn failed_start_cleans_up_and_retry_after_port_release_works() -> Check {
    let f = Fixture::new()?;
    let occupied = (20000..30000)
        .find_map(|port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).ok())
        .ok_or("no free supported fixture port")?;
    let port = occupied.local_addr()?.port();
    let config = f.home.join("config.toml");
    let original = fs::read_to_string(&config)?;
    let replaced = original
        .lines()
        .map(|line| {
            if line.starts_with("listen_port =") {
                format!("listen_port = {port}")
            } else {
                line.into()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    require(
        replaced != original,
        "fixture did not select the occupied port",
    )?;
    fs::write(&config, replaced)?;
    let (status, _) = f.launch("failed-up", &["up"], None)?.wait()?;
    require(
        !status.success(),
        "startup reported success while its configured port was occupied",
    )?;
    require(
        !f.home.join("endpoint.json").exists(),
        "failed startup left a published endpoint",
    )?;
    drop(occupied);
    f.checked("retry-up", &["up"])?;
    let host = f.host()?;
    f.only_host(&host)?;
    f.stop("retry-down")
}
#[test]
fn restart_publishes_a_new_native_owner_after_witnessed_exit() -> Check {
    let f = Fixture::new()?;
    f.checked("initial-up", &["up"])?;
    let first = f.host()?;
    f.stop("initial-down")?;
    f.checked("restart-up", &["up"])?;
    let second = f.host()?;
    require(
        first != second,
        "restart reused the stopped native instance",
    )?;
    f.only_host(&second)?;
    f.stop("restart-down")
}
#[test]
fn public_stop_witnesses_native_exit_and_retires_the_endpoint() -> Check {
    let f = Fixture::new()?;
    f.checked("up", &["up"])?;
    f.stop("down")
}
