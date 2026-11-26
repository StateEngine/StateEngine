//! Owned system OpenSSH commands, file transfers and bounded diagnostics.
//! Pairing, image verification and publication remain with their callers.
use se_harness::child_io::Child;
use se_remote::{
    channel::{unavailable, unavailable_with_next_step},
    ssh::validate_destination,
};
use se_types::{Result, SeError};
use std::{
    io,
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, ReadBuf},
    process::Command,
    time::timeout,
};
mod diagnostics;
mod sftp;
mod transfer;
#[cfg(all(test, windows))]
mod windows_stdout_eof;
pub use diagnostics::Diagnostics;
use diagnostics::read_errors;
pub use transfer::upload;

pub fn client(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::from(se_proc::background_command(program));
    command.kill_on_drop(true);
    // Every caller replaces stdio. A Windows SSH login's inherited descriptor
    // table describes the login pipes, not this child's new handles.
    #[cfg(windows)]
    command.env_remove("c28fc6f98a2c44abbbd89d6a3037d0d9_POSIX_FD_STATE");
    command
}

/// The bound a bootstrap probe waits before its refusal names the evidence.
const BOOTSTRAP_BOUND: Duration = Duration::from_secs(25);

/// One fixed SSH command: the exit status, bounded stdout, and a sanitized
/// tail of the client's stderr. The tail keeps a refusal from hiding the
/// cause (issue 381: "remote platform discovery failed" over a refused key).
#[derive(Debug)]
pub struct SshOutcome {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr_tail: String,
}

/// What the deadline refusal can still know once the readers are dropped:
/// the bounded bytes each pipe carried and whether each had closed. Issue
/// 364: the old refusal discarded all of this, so a silent running client
/// read like an exited client whose descendant still holds a pipe.
#[derive(Default)]
struct DeadlineEvidence {
    stdout: Vec<u8>,
    stderr_bytes: u64,
    stdout_closed: bool,
    stderr_closed: bool,
}

pub async fn command(destination: &str, command: String) -> Result<SshOutcome> {
    run("ssh", destination, command, BOOTSTRAP_BOUND).await
}

async fn run(
    program: &str,
    destination: &str,
    command: String,
    bound: Duration,
) -> Result<SshOutcome> {
    validate_destination(destination)?;
    let mut child = se_harness::child_io::spawn(
        client(program)
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                destination,
                &command,
            ])
            .stdin(Stdio::null()),
        se_harness::child_io::Pipes {
            stdin: false,
            stdout: true,
            stderr: true,
        },
    )
    .await
    .map_err(|_| unavailable("cannot start the system SSH file-transfer client"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| unavailable("SSH output pipe absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| unavailable("SSH error pipe absent"))?;
    let evidence = Arc::new(Mutex::new(DeadlineEvidence::default()));
    let result = timeout(bound, {
        async {
            let ev = Arc::clone(&evidence);
            let (_, stderr_tail) = tokio::try_join!(
                drain_stdout(stdout, &ev),
                drain_stderr(destination, stderr, &ev)
            )?;
            // The cap refuses before the join even when the client is still
            // alive; the check reads the evidence, it does not take it.
            if ev
                .lock()
                .map(|seen| seen.stdout.len() > 65536)
                .unwrap_or(false)
            {
                return Err(unavailable(
                    "SSH output exceeded its bounded bootstrap response",
                ));
            }
            let status = child
                .wait()
                .await
                .map_err(|_| unavailable("SSH completion could not be observed"))?;
            // The evidence keeps every observed byte until the child is joined,
            // so a deadline refusal below still counts them.
            let stdout = ev
                .lock()
                .map(|mut seen| std::mem::take(&mut seen.stdout))
                .unwrap_or_default();
            Ok(SshOutcome {
                success: status.success(),
                stdout,
                stderr_tail,
            })
        }
    })
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        other => {
            // An exited client with open pipes (a descendant holds a write
            // end) is a different failure than a running one; the refusal
            // says which.
            let refusal = match child.try_wait() {
                Ok(Some(_status)) => deadline_refusal(&evidence, bound, "had already exited"),
                _ => {
                    close(&mut child).await?;
                    deadline_refusal(&evidence, bound, "was still running")
                }
            };
            match other {
                Ok(Err(error)) => Err(error),
                _ => Err(refusal),
            }
        }
    }
}

/// Bounded stdout drain: the cap stays the reader's stop condition, and the
/// pipe feeds the deadline evidence as it is read.
async fn drain_stdout(stdout: impl AsyncRead + Unpin, ev: &Mutex<DeadlineEvidence>) -> Result<()> {
    let mut limited = stdout.take(65537);
    let mut chunk = [0u8; 8192];
    loop {
        let count = limited
            .read(&mut chunk)
            .await
            .map_err(|_| unavailable("SSH output could not be read"))?;
        let mut evidence = match ev.lock() {
            Ok(seen) => seen,
            // A poisoned evidence lock degrades to missing counts; the
            // drain itself still completes.
            Err(_) if count == 0 => return Ok(()),
            Err(_) => continue,
        };
        if count == 0 {
            // take() also reports zero at the cap; only a short read closed.
            evidence.stdout_closed = evidence.stdout.len() < 65537;
            return Ok(());
        }
        evidence.stdout.extend_from_slice(&chunk[..count]);
    }
}

/// Bounded stderr drain with the tail behavior refusals already rely on; the
/// counting wrapper keeps the deadline evidence current as bytes arrive.
async fn drain_stderr(
    destination: &str,
    stderr: impl AsyncRead + Unpin,
    ev: &Arc<Mutex<DeadlineEvidence>>,
) -> Result<String> {
    read_errors(
        destination,
        Counting {
            inner: stderr,
            ev: Arc::clone(ev),
        },
    )
    .await
}

struct Counting<T: AsyncRead + Unpin> {
    inner: T,
    ev: Arc<Mutex<DeadlineEvidence>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Counting<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let added = buf.filled().len() - before;
            if let Ok(mut seen) = self.ev.lock() {
                if added == 0 {
                    seen.stderr_closed = true;
                } else {
                    seen.stderr_bytes = seen.stderr_bytes.saturating_add(added as u64);
                }
            }
        }
        poll
    }
}

/// The deadline refusal: the bound, what each pipe carried and whether it
/// had closed, and whether the client was still alive when it hit.
fn deadline_refusal(ev: &Mutex<DeadlineEvidence>, bound: Duration, child_state: &str) -> SeError {
    let (stdout, stdout_closed, stderr, stderr_closed) = ev
        .lock()
        .map(|seen| {
            (
                seen.stdout.len(),
                seen.stdout_closed,
                seen.stderr_bytes,
                seen.stderr_closed,
            )
        })
        // A poisoned evidence lock degrades to absent counts; the refusal
        // still names the bound and the client state.
        .unwrap_or((0, false, 0, false));
    let number = bound.as_secs();
    let unit = if number == 1 { "second" } else { "seconds" };
    unavailable_with_next_step(
        &format!(
            "SSH bootstrap exceeded {number} {unit}: {stdout} stdout bytes ({}), {stderr} stderr bytes ({}); the client {child_state} at the deadline",
            pipe_state(stdout_closed),
            pipe_state(stderr_closed),
        ),
        "Check the saved SSH destination and machine name, then retry the bootstrap.",
    )
}

fn pipe_state(closed: bool) -> &'static str {
    if closed {
        "pipe closed"
    } else {
        "pipe still open"
    }
}

/// A failed command retains custody until this specific native child is joined.
pub async fn close(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .map_err(|_| unavailable("owned SSH process custody is unreadable"))?
        .is_none()
    {
        child
            .start_kill()
            .map_err(|_| unavailable("cannot stop the owned SSH process"))?;
    }
    child
        .wait()
        .await
        .map_err(|_| unavailable("cannot join the owned SSH process"))?;
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions retain the failing native operation"
)]
mod tests {
    use super::*;
    use se_types::Detail;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_SCRIPT: AtomicUsize = AtomicUsize::new(0);

    fn script(body: &str) -> std::path::PathBuf {
        let name = format!(
            "se-host-ssh-deadline-{}-{}.sh",
            std::process::id(),
            NEXT_SCRIPT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn deadline_reason(error: SeError) -> String {
        match error.body.detail() {
            Detail::ListenerUnavailable(detail) => detail.reason.clone(),
            other => panic!("expected listener-unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deadline_names_a_silent_running_client() {
        let program = script("exec sleep 60");
        let error = run(
            program.to_str().unwrap(),
            "localhost",
            "uname -sm".into(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        let reason = deadline_reason(error);
        assert!(
            reason.contains("SSH bootstrap exceeded 2 seconds"),
            "{reason}"
        );
        assert!(
            reason.contains("0 stdout bytes (pipe still open)"),
            "{reason}"
        );
        assert!(
            reason.contains("0 stderr bytes (pipe still open)"),
            "{reason}"
        );
        assert!(
            reason.contains("the client was still running at the deadline"),
            "{reason}"
        );
        std::fs::remove_file(&program).ok();
    }

    #[tokio::test]
    async fn deadline_names_an_exited_client_holding_its_pipe() {
        // The descendant keeps the stdout write end open after the client
        // exits; the refusal must say the client was gone, not running.
        let program = script("(sleep 8) &\nprintf 'partial\\n'\nexit 0");
        let error = run(
            program.to_str().unwrap(),
            "localhost",
            "uname -sm".into(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        let reason = deadline_reason(error);
        assert!(
            reason.contains("SSH bootstrap exceeded 2 seconds"),
            "{reason}"
        );
        assert!(
            reason.contains("8 stdout bytes (pipe still open)"),
            "{reason}"
        );
        assert!(
            reason.contains("the client had already exited at the deadline"),
            "{reason}"
        );
        std::fs::remove_file(&program).ok();
    }

    #[tokio::test]
    async fn deadline_keeps_counts_from_a_client_that_closes_its_pipes() {
        // The client reports, closes both pipes, and stays alive; the refusal
        // must count what the pipes carried, not zero.
        let program = script("printf 'hello'\nprintf 'err\\n' 1>&2\nexec 1>&- 2>&-\nsleep 60");
        let error = run(
            program.to_str().unwrap(),
            "localhost",
            "uname -sm".into(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        let next_step = match error.body.detail() {
            Detail::ListenerUnavailable(detail) => detail.next_step.clone(),
            other => panic!("expected listener-unavailable, got {other:?}"),
        };
        let reason = deadline_reason(error);
        assert!(reason.contains("5 stdout bytes (pipe closed)"), "{reason}");
        assert!(reason.contains("4 stderr bytes (pipe closed)"), "{reason}");
        assert!(
            reason.contains("the client was still running at the deadline"),
            "{reason}"
        );
        assert!(next_step.contains("retry the bootstrap"), "{next_step}");
        std::fs::remove_file(&program).ok();
    }

    #[tokio::test]
    async fn bounded_stdout_still_refuses_before_the_deadline() {
        let program = script("head -c 70000 /dev/zero");
        let error = run(
            program.to_str().unwrap(),
            "localhost",
            "uname -sm".into(),
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert_eq!(
            deadline_reason(error),
            "SSH output exceeded its bounded bootstrap response"
        );
        std::fs::remove_file(&program).ok();
    }

    #[tokio::test]
    async fn completed_probe_keeps_its_outcome() {
        let program = script("printf 'ok\\n'");
        let outcome = run(
            program.to_str().unwrap(),
            "localhost",
            "uname -sm".into(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.stdout, b"ok\n");
        assert_eq!(outcome.stderr_tail, "");
        std::fs::remove_file(&program).ok();
    }
}
