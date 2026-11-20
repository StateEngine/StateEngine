//! The bounded `git rev-list --count` history walk and its whole-pipe reads.
//! Moved unchanged from the repository state observer.
use super::{COUNT_RETAIN, STDERR_RETAIN, bounded_exit, configured, stderr_tail};
use se_core::scope;
use se_types::Result;
use std::{io, path::Path, process::Stdio, time::Instant};
use tokio::io::AsyncReadExt;

/// The commit count's result: a counted history, a history walk that outlived
/// the deadline, or the absence of a Git binary on this machine.
pub(super) enum CountRead {
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
pub(super) async fn observe_count(root: &Path, head: &str, deadline: Instant) -> Result<CountRead> {
    let deadline = tokio::time::Instant::from(deadline);
    let mut command = tokio::process::Command::from(se_proc::background_command("git"));
    configured(root, &mut command)
        .args(["rev-list", "--count", head])
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
