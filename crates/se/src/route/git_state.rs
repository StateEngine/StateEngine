//! Bounded read-only observation of an existing Git repository: the branch,
//! the commit count reachable from HEAD and whether uncommitted changes are
//! present. Every Git invocation passes a top-precedence
//! `core.fsmonitor=false` command parameter, which beats both repository
//! files and an inherited `GIT_CONFIG_PARAMETERS`, and keeps output bounded,
//! so the observer can never execute repository configuration, buffer an
//! unbounded working tree, or stretch the observation against a pipe a
//! retained descriptor keeps open.
use se_core::{ops::GitView, scope};
use se_types::{Result, SeError};
use std::{
    io,
    path::Path,
    process::{Command, ExitStatus, Output, Stdio},
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

const STATUS_OBSERVATION_DEADLINE: Duration = Duration::from_secs(10);
const STDERR_RETAIN: usize = 4096;
const STDERR_TAIL: usize = 160;

pub fn observe(root: &Path) -> Result<Option<GitView>> {
    if !root.is_dir() {
        return Ok(None);
    }
    let mut candidate = Some(root);
    let mut registered = false;
    while let Some(path) = candidate {
        match std::fs::symlink_metadata(path.join(".git")) {
            Ok(_) => {
                registered = true;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(scope::unreadable(
                    "Git repository metadata",
                    &error.to_string(),
                ));
            }
        }
        candidate = path.parent();
    }
    if !registered {
        return Ok(None);
    }
    let symbolic = match run(root, &["symbolic-ref", "-q", "HEAD"]) {
        Spawn::Output(output) => output,
        // Git metadata is present but the machine has no Git binary: the
        // state is absent to this machine, not unreadable.
        Spawn::Missing => return Ok(None),
        Spawn::Unreadable(error) => return Err(error),
    };
    let full_branch = if symbolic.status.success() {
        Some(text(&symbolic)?)
    } else if symbolic.status.code() == Some(1) {
        None
    } else {
        return Err(scope::unreadable(
            "Git HEAD",
            "symbolic HEAD could not be read",
        ));
    };
    let head = match run(root, &["rev-parse", "--verify", "--quiet", "HEAD"]) {
        Spawn::Output(output) => output,
        Spawn::Missing => return Ok(None),
        Spawn::Unreadable(error) => return Err(error),
    };
    let (head, commits) = if head.status.success() {
        let value = text(&head)?;
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(scope::unreadable(
                "Git HEAD",
                "Git returned an invalid object identity",
            ));
        }
        let count = match run(root, &["rev-list", "--count", "HEAD"]) {
            Spawn::Output(output) => output,
            Spawn::Missing => return Ok(None),
            Spawn::Unreadable(error) => return Err(error),
        };
        if !count.status.success() {
            return Err(scope::unreadable(
                "Git HEAD",
                "commit count lookup failed; preserve the repository and restore access",
            ));
        }
        let count = text(&count)?
            .parse::<u64>()
            .map_err(|_| scope::unreadable("Git HEAD", "Git returned an invalid commit count"))?;
        (Some(value), Some(count))
    } else if head.status.code() == Some(1) {
        let branch = full_branch.as_deref().ok_or_else(|| {
            scope::unreadable("Git HEAD", "detached HEAD does not resolve to a commit")
        })?;
        let exists = match run(root, &["show-ref", "--verify", "--quiet", branch]) {
            Spawn::Output(output) => output,
            Spawn::Missing => return Ok(None),
            Spawn::Unreadable(error) => return Err(error),
        };
        if exists.status.code() != Some(1) {
            return Err(scope::unreadable(
                "Git HEAD",
                "a present or unreadable branch failed to resolve",
            ));
        }
        (None, None)
    } else {
        return Err(scope::unreadable(
            "Git HEAD",
            "commit lookup failed; preserve the repository and restore access",
        ));
    };
    let uncommitted = match &head {
        Some(_) => dirty(root)?,
        None => None,
    };
    Ok(Some(GitView {
        head,
        branch: full_branch.map(|value| {
            value
                .strip_prefix("refs/heads/")
                .unwrap_or(&value)
                .to_owned()
        }),
        commits,
        uncommitted,
    }))
}

/// Observe only whether the working tree has uncommitted changes, streaming
/// `git status --porcelain` instead of buffering it. stdout and stderr are
/// read by separate tasks, and every wait in the observation — first byte,
/// stderr drain, child exit, task closure — is bounded by one deadline, so
/// neither a child that fills a pipe nor a descendant that retains
/// inherited descriptors can stretch it. Dirty is settled by the first
/// stdout byte: the child is then killed and reaped and both reader tasks
/// are awaited to completion before the fact is returned. Clean requires
/// the command to finish empty; a run that outgrows the bounded
/// observation is reported as unknown, and a pipe read failure is preserved
/// and reported as unreadable rather than converted to zero.
fn dirty(root: &Path) -> Result<Option<bool>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| scope::unreadable("Git repository observation", &error.to_string()))?;
    runtime.block_on(observe_dirty(root))
}

async fn observe_dirty(root: &Path) -> Result<Option<bool>> {
    let deadline = tokio::time::Instant::from(Instant::now() + STATUS_OBSERVATION_DEADLINE);
    let mut command = tokio::process::Command::new("git");
    configured(root, &mut command)
        .args(["status", "--porcelain"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| scope::unreadable("Git repository observation", &e.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        scope::unreadable("Git working tree", "status output pipe was not attached")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        scope::unreadable("Git working tree", "status error pipe was not attached")
    })?;
    let stdout_task = tokio::spawn(stdout_first_byte(stdout, deadline));
    let stderr_task = tokio::spawn(stderr_retain(stderr, deadline));

    let outcome = stdout_task.await.map_err(|error| {
        scope::unreadable(
            "Git working tree",
            &format!("status reader failed: {error}"),
        )
    })?;
    match outcome {
        StdoutOutcome::Dirty => {
            // The first byte already proves dirty; kill and reap the child,
            // then witness the stderr reader closing itself.
            let _ = child.kill().await;
            let _ = bounded_exit(&mut child, deadline).await;
            let _ = stderr_task.await;
            Ok(Some(true))
        }
        StdoutOutcome::ReadFailure(reason) => {
            let _ = child.kill().await;
            let _ = bounded_exit(&mut child, deadline).await;
            let stderr = stderr_task.await.unwrap_or(StderrOutcome {
                retained: Vec::new(),
                read_failure: None,
            });
            let mut read_failures = vec![format!("stdout read failed: {reason}")];
            if let Some(failure) = &stderr.read_failure {
                read_failures.push(format!("stderr read failed: {failure}"));
            }
            Err(scope::unreadable(
                "Git working tree",
                &failure_detail(&[], &read_failures),
            ))
        }
        StdoutOutcome::Empty => match bounded_exit(&mut child, deadline).await {
            Some(Ok(status)) if status.success() => {
                let _ = stderr_task.await;
                Ok(Some(false))
            }
            Some(Ok(_status)) => {
                let stderr = stderr_task.await.unwrap_or(StderrOutcome {
                    retained: Vec::new(),
                    read_failure: None,
                });
                let mut read_failures = Vec::new();
                if let Some(failure) = &stderr.read_failure {
                    read_failures.push(format!("stderr read failed: {failure}"));
                }
                Err(scope::unreadable(
                    "Git working tree",
                    &failure_detail(&stderr.retained, &read_failures),
                ))
            }
            Some(Err(error)) => {
                let _ = child.kill().await;
                let _ = stderr_task.await;
                Err(scope::unreadable("Git working tree", &error.to_string()))
            }
            None => {
                // The deadline passed before the child exited: the working
                // tree state is unknown, so kill and reap the child and
                // witness the reader closing.
                let _ = child.kill().await;
                let _ = bounded_exit(&mut child, deadline).await;
                let _ = stderr_task.await;
                Ok(None)
            }
        },
        StdoutOutcome::Deadline => {
            // No byte settled the fact before the deadline.
            let _ = child.kill().await;
            let _ = bounded_exit(&mut child, deadline).await;
            let _ = stderr_task.await;
            Ok(None)
        }
    }
}

/// The bounded stdout read: dirty at the first output byte, empty when the
/// pipe closes first, unreadable when the pipe read itself fails, and
/// deadline when a retained descriptor keeps the pipe open too long.
enum StdoutOutcome {
    Dirty,
    Empty,
    ReadFailure(String),
    Deadline,
}

/// The stderr reader's single outcome: a bounded retained tail and the read
/// failure if the pipe itself failed.
struct StderrOutcome {
    retained: Vec<u8>,
    read_failure: Option<String>,
}

async fn stdout_first_byte(
    mut stdout: tokio::process::ChildStdout,
    deadline: tokio::time::Instant,
) -> StdoutOutcome {
    let mut buffer = [0u8; 8192];
    tokio::select! {
        result = stdout.read(&mut buffer) => match result {
            Ok(0) => StdoutOutcome::Empty,
            Ok(_) => StdoutOutcome::Dirty,
            Err(error) => StdoutOutcome::ReadFailure(error.to_string()),
        },
        () = tokio::time::sleep_until(deadline) => StdoutOutcome::Deadline,
    }
}

/// Drain the stderr pipe until EOF, a read failure, or the observation
/// deadline, retaining a bounded tail either way.
async fn stderr_retain(
    mut stderr: tokio::process::ChildStderr,
    deadline: tokio::time::Instant,
) -> StderrOutcome {
    let mut retained: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut read_failure: Option<String> = None;
    loop {
        tokio::select! {
            result = stderr.read(&mut buffer) => match result {
                Ok(0) => break,
                Ok(read) => {
                    for &byte in &buffer[..read] {
                        if retained.len() < STDERR_RETAIN {
                            retained.push(byte);
                        }
                    }
                }
                Err(error) => {
                    read_failure = Some(error.to_string());
                    break;
                }
            },
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    StderrOutcome {
        retained,
        read_failure,
    }
}

/// Wait for the child to exit or the deadline to pass; `None` reports the
/// deadline first, leaving the child for the caller to kill and reap.
async fn bounded_exit(
    child: &mut tokio::process::Child,
    deadline: tokio::time::Instant,
) -> Option<io::Result<ExitStatus>> {
    tokio::select! {
        result = child.wait() => Some(result),
        () = tokio::time::sleep_until(deadline) => None,
    }
}

/// The outcome of one bounded Git invocation. `Missing` keeps a spawn that
/// found no Git binary distinct from a command that ran and failed: the
/// observation reports the state as absent, not unreadable.
enum Spawn {
    Output(Output),
    Missing,
    Unreadable(SeError),
}
fn run(root: &Path, args: &[&str]) -> Spawn {
    let mut command = Command::new("git");
    configured(root, &mut command).args(args);
    match command.output() {
        Ok(output) => Spawn::Output(output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Spawn::Missing,
        Err(error) => Spawn::Unreadable(scope::unreadable(
            "Git repository observation",
            &error.to_string(),
        )),
    }
}

/// The flags every observation call shares. Both Git command builders —
/// std for the buffered metadata calls, tokio for the streaming status —
/// implement exactly this overlap, so one configuration governs both.
trait GitCommand {
    fn git_arg<S: AsRef<std::ffi::OsStr> + Clone>(&mut self, value: S) -> &mut Self;
    fn git_env(&mut self, key: &str, value: &str) -> &mut Self;
    fn git_env_remove(&mut self, key: &str) -> &mut Self;
}

impl GitCommand for Command {
    fn git_arg<S: AsRef<std::ffi::OsStr> + Clone>(&mut self, value: S) -> &mut Self {
        self.arg(value)
    }
    fn git_env(&mut self, key: &str, value: &str) -> &mut Self {
        self.env(key, value)
    }
    fn git_env_remove(&mut self, key: &str) -> &mut Self {
        self.env_remove(key)
    }
}

impl GitCommand for tokio::process::Command {
    fn git_arg<S: AsRef<std::ffi::OsStr> + Clone>(&mut self, value: S) -> &mut Self {
        self.arg(value)
    }
    fn git_env(&mut self, key: &str, value: &str) -> &mut Self {
        self.env(key, value)
    }
    fn git_env_remove(&mut self, key: &str) -> &mut Self {
        self.env_remove(key)
    }
}

/// One Git configuration for every observation call: the target root, a
/// top-precedence `core.fsmonitor=false` command parameter that beats both
/// repository files and an inherited `GIT_CONFIG_PARAMETERS`, no lock
/// maintenance, and no repository identity inherited from the caller's
/// environment.
fn configured<'a, C: GitCommand>(root: &Path, command: &'a mut C) -> &'a mut C {
    command
        .git_arg("-c")
        .git_arg("core.fsmonitor=false")
        .git_arg("-C")
        .git_arg(root)
        .git_env("GIT_OPTIONAL_LOCKS", "0")
        .git_env_remove("GIT_DIR")
        .git_env_remove("GIT_WORK_TREE")
        .git_env_remove("GIT_INDEX_FILE")
}

fn text(output: &Output) -> Result<String> {
    if output.stdout.len() > 4096 {
        return Err(SeError::too_large(
            "Git metadata",
            4096,
            output.stdout.len(),
        ));
    }
    std::str::from_utf8(&output.stdout)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| scope::unreadable("Git metadata", "Git returned non-UTF-8 metadata"))
}

fn failure_detail(bytes: &[u8], read_failures: &[String]) -> String {
    let base = "working tree status could not be read; preserve the repository and restore access";
    let mut parts: Vec<&str> = Vec::new();
    let trimmed = String::from_utf8_lossy(bytes).trim().to_owned();
    if !trimmed.is_empty() {
        let mut end = trimmed.len().min(STDERR_TAIL);
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        parts.push(&trimmed[..end]);
    }
    parts.extend(read_failures.iter().map(String::as_str));
    if parts.is_empty() {
        return base.to_owned();
    }
    format!("{base}: {}", parts.join("; "))
}
