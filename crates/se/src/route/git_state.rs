//! Bounded read-only observation of an existing Git repository: the branch,
//! the commit count reachable from HEAD and whether uncommitted changes are
//! present. Every Git invocation passes a top-precedence
//! `core.fsmonitor=false` command parameter, which beats both repository
//! files and an inherited `GIT_CONFIG_PARAMETERS`, and keeps output bounded,
//! so the observer can never execute repository configuration or buffer an
//! unbounded working tree.
use se_core::{ops::GitView, scope};
use se_types::{Result, SeError};
use std::{
    io::{self, Read},
    path::Path,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

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
    let symbolic = run(root, &["symbolic-ref", "-q", "HEAD"])?;
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
    let head = run(root, &["rev-parse", "--verify", "--quiet", "HEAD"])?;
    let (head, commits) = if head.status.success() {
        let value = text(&head)?;
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(scope::unreadable(
                "Git HEAD",
                "Git returned an invalid object identity",
            ));
        }
        let count = run(root, &["rev-list", "--count", "HEAD"])?;
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
        let exists = run(root, &["show-ref", "--verify", "--quiet", branch])?;
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
/// `git status --porcelain` instead of buffering it. Dirty is settled by the
/// first output byte: the child is then killed and reaped, so a status that
/// hangs after emitting a dirty line still settles in milliseconds. Clean
/// requires the command to finish empty; a run that outgrows the bounded
/// observation is reported as unknown, and a pipe read failure is reported
/// as unreadable rather than converted to zero.
fn dirty(root: &Path) -> Result<Option<bool>> {
    let mut command = Command::new("git");
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
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut stdout = io::BufReader::new(stdout);
        let mut stderr = io::BufReader::new(stderr);
        let mut first = [0u8; 8192];
        let outcome = match stdout.read(&mut first) {
            Err(error) => Outcome::Unreadable(error.to_string()),
            Ok(0) => {
                let mut retained: Vec<u8> = Vec::new();
                let mut buffer = [0u8; 8192];
                loop {
                    match stderr.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            for &byte in &buffer[..read] {
                                if retained.len() < STDERR_RETAIN {
                                    retained.push(byte);
                                }
                            }
                        }
                    }
                }
                Outcome::Clean { stderr: retained }
            }
            Ok(_) => Outcome::Dirty,
        };
        let dirty = matches!(outcome, Outcome::Dirty);
        let _ = sender.send(outcome);
        if dirty {
            // The main thread now kills the child; drain both pipes through
            // a bounded buffer so this thread cannot outlive the observation.
            drain(&mut stdout);
            drain(&mut stderr);
        }
    });
    let started = Instant::now();
    let outcome = match receiver.recv_timeout(STATUS_OBSERVATION_DEADLINE) {
        Ok(outcome) => outcome,
        Err(_) => {
            reap(&mut child);
            return Ok(None);
        }
    };
    match outcome {
        Outcome::Dirty => {
            // The first byte already proves dirty; kill and reap the child,
            // which may still be running, so the fact settles at first byte.
            reap(&mut child);
            Ok(Some(true))
        }
        Outcome::Clean { stderr } => {
            let deadline = started + STATUS_OBSERVATION_DEADLINE;
            match bounded_wait(&mut child, deadline) {
                Ok(Some(status)) if status.success() => Ok(Some(false)),
                Ok(Some(_status)) => Err(scope::unreadable(
                    "Git working tree",
                    &failure_detail(&stderr),
                )),
                Ok(None) => {
                    reap(&mut child);
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        }
        Outcome::Unreadable(reason) => {
            reap(&mut child);
            Err(scope::unreadable("Git working tree", &reason))
        }
    }
}

/// One outcome of the streaming status observation: dirty at the first
/// output byte, clean with a bounded stderr tail once the pipes close, or
/// unreadable when the stdout pipe itself fails.
enum Outcome {
    Dirty,
    Clean { stderr: Vec<u8> },
    Unreadable(String),
}

/// Kill the child if it is still running and reap it exactly once.
fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Poll the child until it exits or the deadline passes; `Ok(None)` reports
/// the deadline first, leaving the child to be reaped by the caller.
fn bounded_wait(child: &mut Child, deadline: Instant) -> Result<Option<ExitStatus>> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                return Err(scope::unreadable("Git working tree", &error.to_string()));
            }
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Discard everything a pipe still carries, using a bounded buffer.
fn drain<R: Read>(reader: &mut R) {
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn run(root: &Path, args: &[&str]) -> Result<Output> {
    let mut command = Command::new("git");
    configured(root, &mut command).args(args);
    command
        .output()
        .map_err(|e| scope::unreadable("Git repository observation", &e.to_string()))
}

/// One Git configuration for every observation call: the target root, a
/// top-precedence `core.fsmonitor=false` command parameter that beats both
/// repository files and an inherited `GIT_CONFIG_PARAMETERS`, no lock
/// maintenance, and no repository identity inherited from the caller's
/// environment.
fn configured<'a>(root: &Path, command: &'a mut Command) -> &'a mut Command {
    command
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-C")
        .arg(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
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

fn failure_detail(bytes: &[u8]) -> String {
    let base = "working tree status could not be read; preserve the repository and restore access";
    let trimmed = String::from_utf8_lossy(bytes).trim().to_owned();
    if trimmed.is_empty() {
        return base.to_owned();
    }
    let mut end = trimmed.len().min(STDERR_TAIL);
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{base}: {}", &trimmed[..end])
}
