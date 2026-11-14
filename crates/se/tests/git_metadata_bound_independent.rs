//! Drive init's earliest Git check through the real CLI on native runners.
#![cfg(any(target_os = "linux", windows))]
#[allow(dead_code, reason = "The identity consumer is shared with the CLI.")]
#[path = "../src/route/git_identity.rs"]
mod git_identity;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
type Check = Result<(), Box<dyn std::error::Error>>;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("metadata-review-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        for dir in ["bin", "repo", "home"] {
            fs::create_dir(root.join(dir))?;
        }
        Ok(Self(root))
    }
    fn compile_git(&self) -> Check {
        let output = Command::new("rustc")
            .args(["--edition=2024", "--crate-name", "git_fixture"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/judges/git_metadata_fixture.rs"
            ))
            .arg("-o")
            .arg(
                self.0
                    .join("bin")
                    .join(if cfg!(windows) { "git.exe" } else { "git" }),
            )
            .output()?;
        assert!(
            output.status.success(),
            "fixture did not compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    fn release(&self) -> Check {
        fs::write(self.0.join("release"), b"release")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        for name in ["git", "retainer"] {
            let path = self.0.join(format!("{name}.pid"));
            if !path.exists() {
                continue;
            }
            let pid = se_proc::ProcessId(fs::read_to_string(path)?.parse()?);
            loop {
                let read = se_proc::read_process_until(
                    se_types::MachineId::new("metadata-fixture")?,
                    pid,
                    deadline,
                )
                .map_err(|error| format!("fixture process read: {error:?}"))?;
                match read {
                    se_proc::ProcessRead::Absent { .. }
                    | se_proc::ProcessRead::ExitedRecord { .. } => break,
                    se_proc::ProcessRead::Present(value)
                        if value.identity.image
                            != fs::canonicalize(self.0.join("bin").join(if cfg!(windows) {
                                "git.exe"
                            } else {
                                "git"
                            }))? =>
                    {
                        break;
                    }
                    _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                    _ => return Err(format!("fixture {name} did not exit").into()),
                }
            }
        }
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.release().is_ok() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn init_case(kind: &str) -> Result<(Fixture, String, bool, Duration), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.compile_git()?;
    let stdout = fs::File::create(fixture.0.join("stdout"))?;
    let stderr = fs::File::create(fixture.0.join("stderr"))?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command
        .args(["--home"])
        .arg(fixture.0.join("state"))
        .args(["init", "--repo"])
        .arg(fixture.0.join("repo"))
        .args(["--name", "Metadata", "--provider", "codex", "--json"])
        .env_clear()
        .env("HOME", fixture.0.join("home"))
        .env("USERPROFILE", fixture.0.join("home"))
        .env("PATH", fixture.0.join("bin"))
        .env("METADATA_FIXTURE_ROOT", &fixture.0)
        .env("METADATA_FIXTURE_KIND", kind)
        .env("GIT_TERMINAL_PROMPT", "1")
        .env("GIT_ASKPASS", "unexpected-prompt")
        .env("SSH_ASKPASS", "unexpected-prompt")
        .env("GCM_INTERACTIVE", "true")
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(stderr)
        .current_dir(fixture.0.join("repo"));
    #[cfg(windows)]
    if let Some(value) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", value);
    }
    let start = Instant::now();
    let mut child = command.spawn()?;
    let mut input = child.stdin.take().ok_or("input pipe")?;
    input.write_all(b"interactive input must not reach Git\n")?;
    let deadline = start + Duration::from_secs(15);
    let timed_out = loop {
        if let Some(status) = child.try_wait()? {
            assert!(!status.success(), "init incorrectly succeeded for {kind}");
            break false;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(input);
    let elapsed = start.elapsed();
    if !timed_out && kind == "hang" {
        let pid = se_proc::ProcessId(fs::read_to_string(fixture.0.join("git.pid"))?.parse()?);
        let read = se_proc::read_process_until(
            se_types::MachineId::new("metadata-fixture")?,
            pid,
            Instant::now() + Duration::from_secs(1),
        )
        .map_err(|error| format!("owned Git exit observation: {error:?}"))?;
        assert!(
            matches!(
                read,
                se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. }
            ),
            "init returned before its exact Git child exited: {read:?}"
        );
    }
    if kind == "pipes" {
        assert!(
            fixture.0.join("retainer.pid").exists(),
            "retained-pipe fixture did not start"
        );
    }
    fixture.release()?;
    let output = format!(
        "{}{}",
        fs::read_to_string(fixture.0.join("stdout"))?,
        fs::read_to_string(fixture.0.join("stderr"))?
    );
    assert!(
        fixture.0.join("git.pid").exists(),
        "init never reached Git: {output}"
    );
    Ok((fixture, output, timed_out, elapsed))
}
fn refusal(kind: &str, reason: &str) -> Check {
    let (_fixture, output, timed_out, elapsed) = init_case(kind)?;
    assert!(
        !timed_out,
        "init exceeded its external watchdog for {kind}: {output}"
    );
    assert!(
        elapsed < Duration::from_secs(14),
        "init did not return within its command and cleanup bound: {elapsed:?}"
    );
    assert!(
        output.contains("Git") && output.contains(reason),
        "wrong refusal for {kind}: {output}"
    );
    assert!(
        output.contains("retry") || output.contains("Retry"),
        "refusal lacks recovery: {output}"
    );
    Ok(())
}
#[test]
fn hanging_git_does_not_hold_init_open() -> Check {
    refusal("hang", "10 seconds")
}
#[test]
fn inherited_pipes_do_not_hold_init_after_git_exits() -> Check {
    refusal("pipes", "10 seconds")
}
#[test]
fn oversized_git_stdout_is_unreadable_before_exit_status_interpretation() -> Check {
    refusal("stdout", "stdout exceeded")
}
#[test]
fn oversized_git_stderr_is_unreadable_before_exit_status_interpretation() -> Check {
    refusal("stderr", "stderr exceeded")
}
#[test]
fn init_disables_prompts_and_closes_git_input() -> Check {
    let (fixture, output, timed_out, _) = init_case("policy")?;
    assert!(!timed_out);
    assert_eq!(fs::read_to_string(fixture.0.join("policy"))?, "safe");
    assert!(
        output.contains("bare Git repository"),
        "safe fixture's normal result was lost: {output}"
    );
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-C",
        ])
        .arg(root)
        .args(args)
        .output()?;
    assert!(
        output.status.success(),
        "real Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().into())
}
#[test]
fn real_repository_identity_survives_move_and_ancestry_checks() -> Check {
    let fixture = Fixture::new()?;
    let original = fixture.0.join("repo");
    assert!(!git_identity::is_bare(&original)?);
    git(&original, &["init", "-b", "main"])?;
    fs::write(original.join("user.txt"), "first\n")?;
    git(&original, &["add", "user.txt"])?;
    git(&original, &["commit", "-m", "Save work."])?;
    let head = git(&original, &["rev-parse", "HEAD"])?;
    git_identity::record(&original, "fixture-project", &head, &Some("main".into()))?;
    let moved = fixture.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::write(moved.join("user.txt"), "second\n")?;
    git(&moved, &["add", "user.txt"])?;
    git(&moved, &["commit", "-m", "Continue work."])?;
    assert_eq!(git_identity::verify(&moved, "fixture-project")?.0, head);
    Ok(())
}
