//! Public commands and native observations in a unique copied distribution.
use se_proc::{NativeState, ProcessId, ProcessIdentity, ProcessRead};
use std::{
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
#[path = "../../../test-support/directory.rs"]
mod directory;
pub type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub struct Fixture {
    pub home: PathBuf,
    pub repo: PathBuf,
    pub image: PathBuf,
    owned: Option<directory::PrivateDirectory>,
}
impl Fixture {
    pub fn new() -> Check<Self> {
        let owned = directory::private_directory()?;
        let root = owned.join("runtime space Ω");
        std::fs::create_dir(&root)?;
        let root = std::fs::canonicalize(root)?;
        let repo = root.join("repository");
        std::fs::create_dir(&repo)?;
        let image = root.join("selected-se");
        std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
        let f = Self {
            home: root.join("state"),
            repo,
            image,
            owned: Some(owned),
        };
        f.ok(&["--help"])?;
        f.ok(&[
            "init",
            "--repo",
            f.repo.to_str().ok_or("repo UTF-8")?,
            "--name",
            "Detached startup control",
        ])?;
        Ok(f)
    }
    pub fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(&self.image);
        c.args(["--json", "--home"])
            .arg(&self.home)
            .args(args)
            .current_dir(&self.repo)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(|s| {
                s.starts_with("SE_")
                    || s.starts_with("STATEENGINE_")
                    || ["CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI"].contains(&s)
            }) {
                c.env_remove(key);
            }
        }
        c
    }
    pub fn call(&self, args: &[&str]) -> Check<Output> {
        finish(self.command(args).spawn()?)
    }
    pub fn ok(&self, args: &[&str]) -> Check<serde_json::Value> {
        let out = self.call(args)?;
        if !out.status.success() {
            return Err(format!(
                "public {args:?} failed: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        if args == ["--help"] {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    }
    pub fn endpoint(&self) -> Check<se_host::EndpointRecord> {
        Ok(se_host::client::endpoint::decode_endpoint(&std::fs::read(
            self.home.join("endpoint.json"),
        )?)?)
    }
    pub fn birth(&self) -> Check<ProcessIdentity> {
        let endpoint = self.endpoint()?;
        let owner = endpoint.epoch.owner.fields();
        let observed = se_proc::read_process(owner.machine.clone(), ProcessId(owner.pid.get()))
            .map_err(|e| format!("native owner read: {e:?}"))?;
        let ProcessRead::Present(observed) = observed else {
            return Err(format!("published host is not live: {observed:?}").into());
        };
        assert_eq!(observed.identity.image, self.image);
        assert!(!matches!(
            observed.state,
            NativeState::Exited | NativeState::ExitedAwaitingReap
        ));
        assert_eq!(self.hosts()?, vec![observed.identity.pid.0]);
        Ok(observed.identity)
    }
    pub fn hosts(&self) -> Check<Vec<u32>> {
        let out = Command::new("/bin/ps")
            .args(["-axo", "pid=,command="])
            .output()?;
        if !out.status.success() {
            return Err("outside process census unreadable".into());
        }
        let marker = self.image.to_str().ok_or("image UTF-8")?;
        let mut found = Vec::new();
        for row in std::str::from_utf8(&out.stdout)?.lines() {
            if row.contains(marker) && row.contains("--stateengine-private-runtime-bootstrap") {
                // Read the entire command before associating this exact pid.
                let pid = row.split_whitespace().next().ok_or("census pid")?.parse()?;
                println!("owned native command: {row}");
                found.push(pid);
            }
        }
        found.sort_unstable();
        Ok(found)
    }
    pub fn down(&self, original: &ProcessIdentity) -> Check {
        let stopped = self.ok(&["down"])?;
        assert_eq!(stopped["complete"], true, "{stopped}");
        assert_eq!(stopped["witness"]["state"], "witnessed", "{stopped}");
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            let read = se_proc::read_process(original.machine.clone(), original.pid)
                .map_err(|e| format!("outside exit read: {e:?}"))?;
            let gone = match read {
                ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. } => true,
                ProcessRead::Present(row) => {
                    row.identity != *original
                        || matches!(
                            row.state,
                            NativeState::Exited | NativeState::ExitedAwaitingReap
                        )
                }
            };
            if gone {
                break;
            }
            if Instant::now() >= until {
                return Err("witnessed host remains live outside writer".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.absent()
    }
    pub fn absent(&self) -> Check {
        assert!(!self.home.join("endpoint.json").try_exists()?);
        assert!(self.hosts()?.is_empty(), "detached child remains");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.home.join("runtime.lock"))?;
        file.try_lock()?;
        file.unlock()?;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = self.call(&["down"]) {
            eprintln!("owned cleanup command failed: {error}");
        }
        if !matches!(self.hosts(),Ok(ref rows) if rows.is_empty()) {
            eprintln!("owned native closure is unproved; preserving fixture state");
            if let Some(owned) = self.owned.take() {
                std::mem::forget(owned);
            }
        }
    }
}
pub fn finish(mut child: Child) -> Check<Output> {
    let until = Instant::now() + Duration::from_secs(45);
    while child.try_wait()?.is_none() {
        if Instant::now() >= until {
            child.kill()?;
            child.wait()?;
            return Err("owned CLI exceeded 45s and was joined".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output()?;
    if out.stdout.len() > 1024 * 1024 || out.stderr.len() > 1024 * 1024 {
        return Err("public output exceeded bound".into());
    }
    Ok(out)
}
pub fn port(f: &Fixture, value: u16) -> Check {
    let path = f.home.join("config.toml");
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let table = config.as_table_mut().ok_or("config table")?;
    let runtime = table
        .entry("runtime")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    runtime
        .as_table_mut()
        .ok_or("runtime config table")?
        .insert("listen_port".into(), toml::Value::Integer(i64::from(value)));
    std::fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}
pub fn successful(out: &Output) -> Check<serde_json::Value> {
    if !out.status.success() {
        return Err(format!(
            "public start refused: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}
