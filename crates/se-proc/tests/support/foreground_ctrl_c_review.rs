//! The real foreground CLI owns its lifetime and closes after output failure.
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
        let candidate = std::env::var_os("SE_W3_SE_BIN").ok_or("exact candidate CLI pin")?;
        fs::copy(candidate, &image)?;
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
#[path = "../../../test-support/directory.rs"]
mod directory;
#[path = "../../../test-support/executable.rs"]
mod executable;
use directory::PrivateDirectory;
use executable::ExecutableCommand;
use std::os::windows::process::CommandExt;

#[cfg(windows)]
#[test]
fn foreground_ctrl_c_releases_the_host() -> Check {
    use windows_sys::Win32::System::{
        Console::{
            CTRL_C_EVENT, GenerateConsoleCtrlEvent, GetConsoleProcessList, SetConsoleCtrlHandler,
        },
        Threading::CREATE_NEW_CONSOLE,
    };

    const OWN_CONSOLE: &str = "SE_JUDGE_FOREGROUND_OWN_CONSOLE";

    if std::env::var_os(OWN_CONSOLE).is_none() {
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "foreground_ctrl_c_review::foreground_ctrl_c_releases_the_host",
                "--nocapture",
            ])
            .env(OWN_CONSOLE, "1")
            .creation_flags(CREATE_NEW_CONSOLE)
            .output()?;
        assert!(
            output.status.success(),
            "isolated console returned {}: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }

    let mut fixture = Fixture::new()?;
    // SAFETY: NULL registers native Ctrl+C ignore only in this isolated driver.
    if unsafe { SetConsoleCtrlHandler(None, 1) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    fixture.spawn()?;
    let child = fixture.child.as_mut().ok_or("missing foreground child")?;
    let pid = child.id();
    let stdout = child.stdout.take().ok_or("missing startup output")?;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let ready: serde_json::Value =
        serde_json::from_str(&receiver.recv_timeout(Duration::from_secs(30))??)?;
    assert_eq!(ready["state"], "running");
    assert_eq!(ready["process"]["pid"], pid);

    let mut attached = [0; 8];
    // SAFETY: the OS receives a writable array and its exact capacity.
    let count = unsafe { GetConsoleProcessList(attached.as_mut_ptr(), attached.len() as u32) };
    assert_eq!(count, 2, "unexpected console membership: {attached:?}");
    assert!(attached[..2].contains(&pid) && attached[..2].contains(&std::process::id()));
    // SAFETY: only the test driver and its owned host share this console.
    if unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let status = fixture.wait()?;
    assert!(
        status.success(),
        "foreground Ctrl+C shutdown returned {status}"
    );
    drop(receiver);
    reader.join().map_err(|_| "startup reader panicked")?;
    fixture.finish()?;

    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/foreground-ctrl-c");
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join("foreground.json"),
        serde_json::to_vec(&serde_json::json!({
            "os": "windows", "run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "foreground_joined": true, "endpoint_removed_and_lease_released": true,
        }))?,
    )?;
    Ok(())
}
