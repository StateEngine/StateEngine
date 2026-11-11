//! Actual Windows image pinning and the two public diagnostic renderers.
#![cfg(windows)]
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check<T = ()> = Result<T, Box<dyn Error>>;

fn command(image: &Path, home: &Path, root: &Path, json: bool) -> Command {
    let mut command = Command::new(image);
    command.arg("--home").arg(home).current_dir(root);
    if json {
        command.arg("--json");
    }
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
    command
}
fn value(output: Output) -> Check<serde_json::Value> {
    assert!(
        output.status.success(),
        "real CLI refused: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
struct Host {
    image: PathBuf,
    home: PathBuf,
    root: PathBuf,
    identity: se_proc::ProcessIdentity,
    stopped: bool,
}
impl Host {
    fn exited(&self) -> Check<bool> {
        match se_proc::NativeProcessRuntime::read_process(
            self.identity.machine.clone(),
            self.identity.pid,
        )
        .map_err(|error| format!("outside owned host observation: {error:?}"))?
        {
            se_proc::ProcessRead::Absent { .. } => Ok(true),
            se_proc::ProcessRead::ExitedRecord {
                pid, boot, start, ..
            } if pid == self.identity.pid
                && boot == self.identity.boot
                && start == self.identity.start =>
            {
                Ok(true)
            }
            se_proc::ProcessRead::Present(value) if value.identity == self.identity => {
                Ok(value.state == se_proc::NativeState::ExitedAwaitingReap)
            }
            _ => Err("host identity changed; refusing another process".into()),
        }
    }
    fn stop(&mut self) -> Check {
        if self.stopped {
            return Ok(());
        }
        if !self.exited()? {
            let output = command(&self.image, &self.home, &self.root, true)
                .arg("down")
                .output_executable()?;
            assert!(
                matches!(output.status.code(), Some(0) | Some(2)),
                "real down refused: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let until = Instant::now() + Duration::from_secs(15);
        while !self.exited()? {
            if Instant::now() >= until {
                return Err("exact owned host did not exit".into());
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
        assert!(
            !self.home.join("endpoint.json").try_exists()?,
            "endpoint not retired"
        );
        let lease = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.home.join("runtime.lock"))?;
        lease.try_lock()?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!(
                "retaining owned host {} and fixture {}: {error}",
                self.identity.pid.0,
                self.home.display()
            );
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn multilink_image_names_the_launch_precondition_and_a_single_link_copy_starts() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = std::env::temp_dir().join(format!(
        "se-image-remedy-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    drop(se_proc::NativeStateFiles::create(&fixture)?);
    let image = fixture.join("multi link runtime.exe");
    let alias = fixture.join("runtime alias.exe");
    let installed = fixture.join("single link installed.exe");
    fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    fs::hard_link(&image, &alias)?;
    fs::copy(&image, &installed)?;
    let home = fixture.join("state");
    let root = fixture.join("repository");
    fs::create_dir(&root)?;
    value(
        command(&installed, &home, &root, true)
            .args(["init", "--name", "image-remedy"])
            .output_executable()?,
    )?;
    for (json, executable) in [(true, &image), (false, &alias)] {
        let output = command(executable, &home, &root, json)
            .arg("up")
            .output_executable()?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "expected Refused: {output:?}"
        );
        let diagnostic = String::from_utf8(output.stderr)?;
        let expected = executable
            .to_str()
            .ok_or("fixture image path is not UTF-8")?;
        assert!(
            diagnostic.contains("error[launch-failed]")
                && diagnostic.contains(expected)
                && diagnostic.contains("single-link regular disk file required")
                && diagnostic.contains("Reinstall StateEngine")
                && diagnostic.contains("copy this executable")
                && diagnostic.contains("single-link file"),
            "wrong image diagnostic: {diagnostic}"
        );
        assert!(
            !diagnostic.contains("Restore access") && !diagnostic.contains("source-unreadable")
        );
        if json {
            let error: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(error["code"], "launch-failed");
            assert_eq!(error["exit"], 1);
            let subject = error["detail"]["subject"]
                .as_str()
                .ok_or("image subject absent")?;
            assert_eq!(fs::canonicalize(subject)?, fs::canonicalize(executable)?);
            assert!(
                error["detail"]["reason"]
                    .as_str()
                    .ok_or("native reason absent")?
                    .contains("single-link regular disk file required")
            );
            let remedy = error["remedy"]["text"].as_str().ok_or("remedy absent")?;
            assert!(remedy.contains("Reinstall StateEngine") && remedy.contains("single-link"));
        } else {
            assert!(
                output.stdout.is_empty(),
                "human refusal contaminated stdout"
            );
        }
        assert!(
            !home.join("endpoint.json").try_exists()?,
            "refusal published a host"
        );
    }
    let started = value(
        command(&installed, &home, &root, true)
            .arg("up")
            .output_executable()?,
    )?;
    assert_eq!(started["state"], "running");
    let endpoint =
        se_host::client::endpoint::decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
    let fields = endpoint.epoch.owner.fields();
    let observed = se_proc::NativeProcessRuntime::read_process(
        fields.machine.clone(),
        se_proc::ProcessId(fields.pid.get()),
    )
    .map_err(|error| format!("native single-link host: {error:?}"))?;
    let se_proc::ProcessRead::Present(observed) = observed else {
        return Err("single-link copy did not start a live host".into());
    };
    let mut host = Host {
        image: installed.clone(),
        home,
        root,
        identity: observed.identity,
        stopped: false,
    };
    assert_eq!(
        fs::canonicalize(&host.identity.image)?,
        fs::canonicalize(&installed)?
    );
    host.stop()?;
    drop(host);
    fs::remove_dir_all(fixture)?;
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
