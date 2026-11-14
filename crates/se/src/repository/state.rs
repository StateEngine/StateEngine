//! Bounded read-only observation of an existing Git repository: the branch,
//! the commit count reachable from HEAD and whether uncommitted changes are
//! present. Every Git invocation passes a top-precedence
//! `core.fsmonitor=false` command parameter, which beats both repository
//! files and an inherited `GIT_CONFIG_PARAMETERS`, and keeps output bounded,
//! so the observer can never execute repository configuration, buffer an
//! unbounded working tree, or stretch the observation against a pipe a
//! retained descriptor keeps open.
use se_core::{ops::GitView, scope};
use se_types::Result;
use std::{
    io,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

const STATUS_OBSERVATION_DEADLINE: Duration = Duration::from_secs(10);
const STDERR_RETAIN: usize = 4096;
const STDERR_TAIL: usize = 160;
/// A commit count is a short decimal number; a bound far above it refuses a
/// hostile or malformed writer instead of buffering it.
const COUNT_RETAIN: usize = 256;

pub fn observe(root: &Path) -> Result<Option<GitView>> {
    let _phase = crate::phase_trace::Phase::new("cli_repository_state");
    let deadline = Instant::now() + STATUS_OBSERVATION_DEADLINE;
    observe_within(root, deadline)
}

/// The observation with its one deadline supplied, so a test can drive the
/// bounded paths without waiting the production bound out.
pub(crate) fn observe_within(root: &Path, deadline: Instant) -> Result<Option<GitView>> {
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
    // One `status --porcelain=v2 --branch` carries HEAD, the branch name and
    // whether the tree is dirty, so the observation costs two Git processes
    // instead of four. Its cost is bounded by the working tree, not the
    // history, and it is settled at the first entry rather than buffered.
    let StatusRead::Known {
        header,
        dirty: observed_dirty,
    } = status_header_within(root, deadline)?
    else {
        // Git metadata is present but this machine has no Git binary: the
        // state is absent to this machine, not unreadable.
        return Ok(None);
    };
    // A dirty fact is only meaningful against a resolved commit; an unborn
    // branch reports no head, no count and no dirty fact. An unresolved dirty
    // fact stays `None`, which reads as unknown rather than clean.
    let uncommitted = if header.head.is_some() {
        observed_dirty
    } else {
        None
    };
    // The commit count shown as "Existing repo: N commits" is its own bounded
    // call; nothing else in the output depends on it.
    let commits = match header.head.as_ref() {
        Some(_) => match commit_count_within(root, deadline)? {
            CountRead::Count(count) => Some(count),
            // A history walk that outlived the deadline leaves the count
            // unknown. A count of zero would claim an empty history, so the
            // fact stays absent and status names it as unknown instead.
            CountRead::Deadline => None,
            // Git went away between the header read and the count: the
            // repository is absent to this machine, not present with an
            // invented count.
            CountRead::Missing => return Ok(None),
        },
        None => None,
    };
    Ok(Some(GitView {
        head: header.head,
        branch: header.branch,
        commits,
        uncommitted,
    }))
}

/// The `--branch` header the observation keeps: the HEAD object identity, or
/// its absence for an unborn branch, and the branch name, or its absence for a
/// detached HEAD.
struct StatusHeader {
    head: Option<String>,
    branch: Option<String>,
}

/// The commit count's result: a counted history, a history walk that outlived
/// the deadline, or the absence of a Git binary on this machine.
enum CountRead {
    Count(u64),
    Deadline,
    Missing,
}

/// Count the commits reachable from HEAD under the observation's deadline.
///
/// `rev-list --count` walks the history, so it is the one call whose cost grows
/// with the repository. It is kept separate so the header and dirty facts never
/// wait on it, and every wait on it — spawn, output, exit — is bounded, so a
/// slow or stuck walk cannot hold `se status` open. A walk that misses the
/// deadline is killed and reaped and reported as unknown, never as zero. Its
/// output is bounded like every other metadata read.
fn commit_count_within(root: &Path, deadline: Instant) -> Result<CountRead> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| scope::unreadable("Git repository observation", &error.to_string()))?;
    runtime.block_on(observe_count(root, deadline))
}

async fn observe_count(root: &Path, deadline: Instant) -> Result<CountRead> {
    let deadline = tokio::time::Instant::from(deadline);
    let mut command = tokio::process::Command::new("git");
    configured(root, &mut command)
        .args(["rev-list", "--count", "HEAD"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(CountRead::Missing),
        Err(error) => {
            return Err(scope::unreadable(
                "Git HEAD",
                &format!("commit count lookup failed: {error}"),
            ));
        }
    };
    let stdout = child.stdout.take().ok_or_else(|| {
        scope::unreadable("Git HEAD", "commit count output pipe was not attached")
    })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| scope::unreadable("Git HEAD", "commit count error pipe was not attached"))?;
    // Both pipes are drained to EOF or the deadline, so a writer that fills
    // either one cannot block the child while the exit wait is outstanding.
    let stdout = super::pipe::stdout(stdout)
        .map_err(|error| scope::unreadable("Git stdout pipe", &error.to_string()))?;
    let stderr = super::pipe::stderr(stderr)
        .map_err(|error| scope::unreadable("Git stderr pipe", &error.to_string()))?;
    let stdout_task = tokio::spawn(retain_bounded(stdout, COUNT_RETAIN, deadline));
    let stderr_task = tokio::spawn(retain_bounded(stderr, STDERR_RETAIN, deadline));
    let exited = bounded_exit(&mut child, deadline).await;
    let output = stdout_task.await.ok();
    let perror = stderr_task.await;
    match exited {
        None => {
            // No count before the deadline: the history may be any size. Kill
            // and reap the child and witness both readers closing.
            let _ = child.kill().await;
            let _ = bounded_exit(&mut child, deadline).await;
            Ok(CountRead::Deadline)
        }
        Some(Err(error)) => {
            let _ = child.kill().await;
            Err(scope::unreadable(
                "Git HEAD",
                &format!("commit count lookup failed: {error}"),
            ))
        }
        Some(Ok(status)) => {
            let output = output
                .ok_or_else(|| scope::unreadable("Git HEAD", "commit count reader failed"))?;
            match output {
                PipeRead::Read(bytes) => {
                    let tail = match &perror {
                        Ok(PipeRead::Read(stderr)) => stderr_tail(stderr),
                        // An unread stderr tail or a stderr that hit the
                        // deadline adds no cause; the status still decides.
                        Ok(PipeRead::Deadline) | Ok(PipeRead::Failure(_)) | Err(_) => String::new(),
                    };
                    if !status.success() {
                        return Err(scope::unreadable(
                            "Git HEAD",
                            &format!(
                                "commit count lookup failed; preserve the repository and restore access{tail}"
                            ),
                        ));
                    }
                    let text = std::str::from_utf8(&bytes).map_err(|_| {
                        scope::unreadable("Git HEAD", "Git returned a non-UTF-8 commit count")
                    })?;
                    let count = text.trim().parse::<u64>().map_err(|_| {
                        scope::unreadable("Git HEAD", "Git returned an invalid commit count")
                    })?;
                    Ok(CountRead::Count(count))
                }
                // The count pipe hit the deadline even though the child exited:
                // its output is incomplete, so the count is unknown rather than
                // an invented zero.
                PipeRead::Deadline => Ok(CountRead::Deadline),
                PipeRead::Failure(reason) => Err(scope::unreadable(
                    "Git HEAD",
                    &format!("commit count read failed: {reason}"),
                )),
            }
        }
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
fn status_header_within(root: &Path, deadline: Instant) -> Result<StatusRead> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| scope::unreadable("Git repository observation", &error.to_string()))?;
    runtime.block_on(observe_status(root, deadline))
}

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
    let mut command = tokio::process::Command::new("git");
    configured(root, &mut command)
        .args(["status", "--porcelain=v2", "--branch"])
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
enum StatusRead {
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

/// The bounded read of a whole pipe: its bytes up to `retain`, or why no whole
/// value was read before the deadline.
enum PipeRead {
    Read(Vec<u8>),
    Deadline,
    Failure(String),
}

/// Read one pipe to EOF or the deadline, buffering at most `retain` bytes.
/// Both the count's stdout and its stderr are drained by this, so neither
/// writer can block on a full pipe while the exit wait is outstanding.
async fn retain_bounded(
    mut pipe: impl tokio::io::AsyncRead + Unpin,
    retain: usize,
    deadline: tokio::time::Instant,
) -> PipeRead {
    let mut retained: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        tokio::select! {
            result = pipe.read(&mut buffer) => match result {
                Ok(0) => return PipeRead::Read(retained),
                Ok(read) => {
                    for &byte in &buffer[..read] {
                        if retained.len() < retain {
                            retained.push(byte);
                        }
                    }
                }
                Err(error) => return PipeRead::Failure(error.to_string()),
            },
            () = tokio::time::sleep_until(deadline) => return PipeRead::Deadline,
        }
    }
}

/// Git's own bounded stderr tail, prefixed for appending to a refusal. Empty
/// when Git said nothing, so a refusal without a cause stays unchanged.
fn stderr_tail(bytes: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(bytes).trim().to_owned();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut end = trimmed.len().min(STDERR_TAIL);
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!(": {}", &trimmed[..end])
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
