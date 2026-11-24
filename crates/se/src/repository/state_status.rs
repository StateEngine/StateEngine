use super::{STDERR_RETAIN, STDERR_TAIL, bounded_exit, configured, observe_blocking};
use se_core::scope;
use se_repository as library;
use se_types::Result;
use std::{io, path::Path, process::Stdio, time::Instant};
use tokio::io::AsyncReadExt;

/// The `--branch` header the observation keeps: the HEAD object identity, or
/// its absence for an unborn branch, and the branch name, or its absence for a
/// detached HEAD.
pub(super) struct StatusHeader {
    pub(super) head: Option<String>,
    pub(super) branch: Option<String>,
}

pub(super) fn status_within(root: &Path, deadline: Instant) -> Result<StatusRead> {
    match library::observe(root, deadline) {
        library::Read::Known(facts) => Ok(StatusRead::Known {
            header: StatusHeader {
                head: facts.head,
                branch: facts.branch,
            },
            dirty: facts.dirty,
        }),
        library::Read::Fallback(reason) if Instant::now() >= deadline => Err(scope::unreadable(
            "Git repository observation",
            &format!(
                "deadline expired before status could be measured; state is unknown: {reason}"
            ),
        )),
        library::Read::Fallback(reason) => observe_blocking(observe_status(root, deadline))
            .map_err(|error| {
                scope::unreadable("Git repository observation", &format!(
                "in-process observation failed: {reason}; command-line observation failed: {error}"
            )).with_cause(error)
            }),
    }
}

/// Observe the repository header and whether the working tree is dirty,
/// streaming `git status --porcelain=v2 --branch` instead of buffering it.
///
/// stdout and stderr are read by separate tasks, and every wait in the
/// observation — header, first entry, stderr drain, child exit, task closure —
/// is bounded by one deadline, so neither a child that fills a pipe nor a
/// descendant that retains inherited descriptors can stretch it.
///
/// `--branch` places `# branch.oid` and `# branch.head` before every entry, so
/// both header facts are known before any working-tree output. The fact is
/// settled at the first entry: the child is then killed and reaped and both
/// reader tasks are awaited to completion before the result is returned. A tree
/// with a hundred thousand changes therefore costs the same as one with a
/// single change, and its entries are never buffered. A pipe read failure is
/// preserved, with Git's own stderr tail, and reported as unreadable rather
/// than converted to zero. A run that cannot settle a fact before the deadline
/// reports that fact as unknown, never as clean or as an unborn branch.
async fn observe_status(root: &Path, deadline: Instant) -> Result<StatusRead> {
    let deadline = tokio::time::Instant::from(deadline);
    let Some(mut child) = spawn_status(root)? else {
        // Git metadata is present but this machine has no Git binary: absent
        // to this machine, not unreadable.
        return Ok(StatusRead::Absent);
    };
    let stdout = child.stdout.take().ok_or_else(|| {
        scope::unreadable("Git working tree", "status output pipe was not attached")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        scope::unreadable("Git working tree", "status error pipe was not attached")
    })?;
    let stdout = super::pipe::stdout(stdout)
        .map_err(|error| scope::unreadable("Git stdout pipe", &error.to_string()))?;
    let stderr = super::pipe::stderr(stderr)
        .map_err(|error| scope::unreadable("Git stderr pipe", &error.to_string()))?;
    let stdout_task = tokio::spawn(read_status(stdout, deadline));
    let stderr_task = tokio::spawn(stderr_retain(stderr, deadline));

    let outcome = stdout_task.await.map_err(|error| {
        scope::unreadable(
            "Git working tree",
            &format!("status reader failed: {error}"),
        )
    })?;
    match outcome {
        StatusOutcome::Settled { header } => {
            // The first entry already proves dirty and the header is complete.
            // Kill and reap the child, then witness the stderr reader closing.
            let _ = child.kill().await;
            let _ = bounded_exit(&mut child, deadline).await;
            let _ = stderr_task.await;
            known(header, Some(true))
        }
        StatusOutcome::ReadFailure(reason) => {
            let _ = child.kill().await;
            let _ = bounded_exit(&mut child, deadline).await;
            let stderr = stderr_task.await.unwrap_or_else(|_| StderrOutcome::empty());
            Err(refusal(
                &stderr,
                vec![format!("stdout read failed: {reason}")],
            ))
        }
        StatusOutcome::Empty { header } => match bounded_exit(&mut child, deadline).await {
            Some(Ok(status)) if status.success() => {
                let _ = stderr_task.await;
                known(header, Some(false))
            }
            Some(Ok(_status)) => {
                let stderr = stderr_task.await.unwrap_or_else(|_| StderrOutcome::empty());
                Err(refusal(&stderr, Vec::new()))
            }
            Some(Err(error)) => {
                let _ = child.kill().await;
                let _ = stderr_task.await;
                Err(scope::unreadable("Git working tree", &error.to_string()))
            }
            None => {
                // The header is complete but the child outlived the deadline,
                // so no entry arrived and no exit status followed: the tree may
                // be clean or dirty. Report the dirty fact as unknown rather
                // than claim the tree is clean.
                let _ = child.kill().await;
                let _ = bounded_exit(&mut child, deadline).await;
                let _ = stderr_task.await;
                known(header, None)
            }
        },
        StatusOutcome::Deadline { header } => {
            // The deadline passed before any entry settled the dirty fact, so
            // the tree may be clean or dirty. A complete header still reports
            // its facts; a header that never finished is unknown, because the
            // fields it left empty would spell an unborn and detached,
            // clean repository.
            let _ = child.kill().await;
            let _ = bounded_exit(&mut child, deadline).await;
            let _ = stderr_task.await;
            known(header, None)
        }
    }
}

/// Spawn the one `status` call, or `None` when this machine has no Git binary.
fn spawn_status(root: &Path) -> Result<Option<tokio::process::Child>> {
    let mut command = tokio::process::Command::from(se_proc::background_command("git"));
    configured(root, &mut command)
        .args(["status", "--porcelain=v2", "--branch", "--no-ahead-behind"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    match command.spawn() {
        Ok(child) => Ok(Some(child)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(scope::unreadable(
            "Git repository observation",
            &error.to_string(),
        )),
    }
}

/// The one refusal a failed read produces: Git's own bounded stderr tail and
/// any reader failure, kept apart rather than collapsed into zero.
fn refusal(stderr: &StderrOutcome, mut read_failures: Vec<String>) -> se_types::SeError {
    if let Some(failure) = &stderr.read_failure {
        read_failures.push(format!("stderr read failed: {failure}"));
    }
    scope::unreadable(
        "Git working tree",
        &failure_detail(&stderr.retained, &read_failures),
    )
}

/// Accept a read only when Git printed both header lines. A `Known` result with
/// an unfinished header would let a missing branch name read as a detached HEAD,
/// or a missing identity as an unborn branch, so it refuses as unknown instead.
/// The refusal names only what is genuinely unknown: an entry that arrived still
/// proved the tree dirty.
fn known(header: HeaderRead, dirty: Option<bool>) -> Result<StatusRead> {
    if header.complete {
        return Ok(StatusRead::Known {
            header: header.header,
            dirty,
        });
    }
    let unknown = if dirty == Some(true) {
        "the branch and HEAD are unknown"
    } else {
        "the branch, HEAD and uncommitted state are unknown"
    };
    Err(scope::unreadable(
        "Git working tree",
        &format!(
            "working tree status stopped before it reported its branch and HEAD; {unknown}. Preserve the repository and retry, or remove whatever keeps the working-tree scan from finishing."
        ),
    ))
}

/// The single `status` read's result: the header facts with a dirty fact that
/// keeps "unknown" distinct from "clean", or the absence of a Git binary on
/// this machine.
pub(super) enum StatusRead {
    Known {
        header: StatusHeader,
        /// `None` when the observation stopped before the fact settled: the
        /// tree may be clean or dirty and the reader says so.
        dirty: Option<bool>,
    },
    /// Git metadata is present but this machine has no Git binary.
    Absent,
}

/// The header lines retained so far. Git prints `# branch.oid` and
/// `# branch.head` before any entry, so `complete` means both were read: an
/// unborn branch said `(initial)` and a detached HEAD said `(detached)`, and
/// anything else is a header that never finished, which is unknown rather than
/// either of those.
struct HeaderRead {
    header: StatusHeader,
    complete: bool,
}

/// The bounded stdout read. The header is complete before the first entry, so
/// `Settled` carries the header and proves the tree dirty together.
enum StatusOutcome {
    Settled { header: HeaderRead },
    Empty { header: HeaderRead },
    ReadFailure(String),
    Deadline { header: HeaderRead },
}

/// Read only the header lines, then settle at the first entry.
///
/// A very large working tree therefore never has its entries buffered: only
/// header bytes are retained, and a bound far above their length refuses a
/// hostile or malformed stream.
async fn read_status(
    mut stdout: impl tokio::io::AsyncRead + Unpin,
    deadline: tokio::time::Instant,
) -> StatusOutcome {
    const HEADER_LIMIT: usize = 4096;
    let mut read = HeaderRead {
        header: StatusHeader {
            head: None,
            branch: None,
        },
        complete: false,
    };
    let mut head_seen = false;
    let mut branch_seen = false;
    let mut pending: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read_bytes = tokio::select! {
            result = stdout.read(&mut buffer) => match result {
                Ok(0) => return StatusOutcome::Empty { header: read },
                Ok(read_bytes) => read_bytes,
                Err(error) => return StatusOutcome::ReadFailure(error.to_string()),
            },
            () = tokio::time::sleep_until(deadline) => return StatusOutcome::Deadline { header: read },
        };
        pending.extend_from_slice(&buffer[..read_bytes]);
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=newline).collect();
            let line = &line[..line.len() - 1];
            if line.is_empty() {
                continue;
            }
            if !line.starts_with(b"#") {
                return StatusOutcome::Settled { header: read };
            }
            let line = match std::str::from_utf8(line) {
                Ok(line) => line,
                Err(_) => {
                    return StatusOutcome::ReadFailure("status header is not UTF-8".into());
                }
            };
            if let Some(value) = line.strip_prefix("# branch.oid ") {
                head_seen = true;
                read.complete = head_seen && branch_seen;
                if value == "(initial)" {
                    read.header.head = None;
                } else if matches!(value.len(), 40 | 64)
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    read.header.head = Some(value.to_owned());
                } else {
                    return StatusOutcome::ReadFailure(
                        "Git returned an invalid object identity".into(),
                    );
                }
            } else if let Some(value) = line.strip_prefix("# branch.head ") {
                branch_seen = true;
                read.complete = head_seen && branch_seen;
                // Git spells a detached HEAD `(detached)`, and a branch may
                // legally carry that exact name, so this header alone cannot
                // tell the two apart: both report no branch name. The commit
                // identity still distinguishes them for anyone who needs it.
                // Resolving it here would cost a fourth Git process.
                read.header.branch = if value == "(detached)" {
                    None
                } else {
                    Some(value.to_owned())
                };
            }
        }
        if pending.len() > HEADER_LIMIT {
            return StatusOutcome::ReadFailure("status header exceeded its bound".into());
        }
    }
}

/// The stderr reader's single outcome: a bounded retained tail and the read
/// failure if the pipe itself failed.
struct StderrOutcome {
    retained: Vec<u8>,
    read_failure: Option<String>,
}

impl StderrOutcome {
    fn empty() -> Self {
        Self {
            retained: Vec::new(),
            read_failure: None,
        }
    }
}

/// Drain the stderr pipe until EOF, a read failure, or the observation
/// deadline, retaining a bounded tail either way.
async fn stderr_retain(
    mut stderr: impl tokio::io::AsyncRead + Unpin,
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
