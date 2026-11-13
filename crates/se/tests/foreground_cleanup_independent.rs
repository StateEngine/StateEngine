//! The real foreground CLI owns its lifetime and closes after output failure.
#![cfg(any(target_os = "linux", windows))]
use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check<T = ()> = Result<T, Box<dyn Error>>;
struct Fixture {
    root: Option<PrivateDirectory>,
    home: PathBuf,
    image: PathBuf,
    child: Option<Child>,
    retain: bool,
}
impl Fixture {
    fn new() -> Check<Self> {
        se_proc::initialize_file_creation_owner()?;
        let root = std::env::temp_dir().join(format!(
            "se-foreground-review-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        drop(se_proc::NativeStateFiles::create(&root)?);
        let root = PrivateDirectory::adopt(root);
        let image = root.join(if cfg!(windows) { "se.exe" } else { "se" });
        fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
        let f = Self {
            home: root.join("state"),
            root: Some(root),
            image,
            child: None,
            retain: false,
        };
        let repo = f.root_path()?.join("repo");
        fs::create_dir(&repo)?;
        fs::write(repo.join("user.txt"), b"preserve this work\n")?;
        let out = f.call(&["init", "--repo", repo.to_str().ok_or("fixture path")?])?;
        assert!(out.status.success(), "init failed: {out:?}");
        Ok(f)
    }
    fn root_path(&self) -> Check<&std::path::Path> {
        self.root
            .as_deref()
            .ok_or_else(|| "missing fixture root".into())
    }

    fn root_display(&self) -> String {
        match self.root_path() {
            Ok(path) => path.display().to_string(),
            Err(error) => format!("<fixture root unavailable: {error}>"),
        }
    }
    fn command(&self) -> Command {
        let mut c = Command::new(&self.image);
        for (key, _) in std::env::vars_os() {
            let text = key.to_string_lossy();
            if text.starts_with("SE_")
                || text.starts_with("STATEENGINE_")
                || text.starts_with("CODEX_")
                || text == "CLAUDECODE"
            {
                c.env_remove(key);
            }
        }
        c.args(["--json", "--home"]).arg(&self.home);
        if let Some(root) = self.root.as_deref() {
            c.current_dir(root);
        }
        c
    }
    fn call(&self, args: &[&str]) -> Check<Output> {
        Ok(self.command().args(args).output_executable()?)
    }
    fn spawn(&mut self) -> Check {
        let diagnostic = fs::File::create(self.root_path()?.join("foreground.stderr"))?;
        self.child = Some(
            self.command()
                .args(["up", "--foreground"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(diagnostic)
                .spawn()?,
        );
        Ok(())
    }
    fn wait(&mut self) -> Check<std::process::ExitStatus> {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.as_mut().ok_or("missing child")?.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= until {
                return Err("foreground child did not join".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn closed(&self) -> Check {
        assert!(
            !self.home.join("endpoint.json").try_exists()?,
            "endpoint survived foreground exit"
        );
        let lease = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.home.join("runtime.lock"))?;
        lease.try_lock()?;
        assert_eq!(
            fs::read(self.root_path()?.join("repo/user.txt"))?,
            b"preserve this work\n"
        );
        Ok(())
    }
    fn finish(mut self) -> Check {
        self.closed()?;
        self.child = None;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.home.join("endpoint.json").exists() {
            match self.call(&["down"]) {
                Ok(out) if out.status.success() => (),
                out => {
                    self.retain = true;
                    eprintln!(
                        "retaining foreground fixture {}: down {out:?}",
                        self.root_display()
                    );
                }
            }
        }
        if self.child.is_some()
            && let Err(error) = self.wait()
        {
            self.retain = true;
            eprintln!(
                "owned foreground child retained at {}: {error}",
                self.root_display()
            );
        }
        if self.retain
            && let Some(root) = self.root.take()
        {
            // Retained state is diagnostic evidence; it must outlive the test.
            std::mem::forget(root);
        }
    }
}
#[test]
fn foreground_pid_stays_the_owner_and_conflicting_start_cannot_replace_it() -> Check {
    let mut f = Fixture::new()?;
    f.spawn()?;
    let child = f.child.as_mut().ok_or("missing child")?;
    let pid = child.id();
    let stdout = child.stdout.take().ok_or("missing startup output")?;
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let first = receive.recv_timeout(Duration::from_secs(30))??;
    let ready: serde_json::Value = serde_json::from_str(&first)?;
    assert_eq!(ready["state"], "running");
    assert_eq!(ready["process"]["pid"], pid);
    let conflict = f.call(&["up", "--foreground"])?;
    assert!(
        !conflict.status.success(),
        "another foreground owner was admitted"
    );
    let status = f.call(&["status"])?;
    assert!(
        status.status.success(),
        "original foreground owner stopped: {status:?}"
    );
    let status: serde_json::Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["runtime"]["process"]["pid"], pid);
    assert!(
        f.child
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_none()
    );
    let down = f.call(&["down"])?;
    assert!(down.status.success(), "down failed: {down:?}");
    assert!(f.wait()?.success());
    reader.join().map_err(|_| "startup reader panicked")?;
    f.finish()
}
#[test]
fn closed_startup_output_leaves_no_host_or_held_home_lease() -> Check {
    let mut f = Fixture::new()?;
    f.spawn()?;
    drop(f.child.as_mut().ok_or("missing child")?.stdout.take());
    assert!(
        !f.wait()?.success(),
        "closed startup output reported success"
    );
    f.finish()
}
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../../test-support/executable.rs"]
mod executable;
use directory::PrivateDirectory;
use executable::ExecutableCommand;
