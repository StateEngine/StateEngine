//! Noninteractive metadata commands share one exit and pipe deadline.
use super::{STDOUT_BOUND, Spawn};
use std::{io, path::Path, process::Output, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    time::{Instant, timeout, timeout_at},
};

const OBSERVATION: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(1);
const STDERR_BOUND: usize = 4096;

pub(super) fn run(root: &Path, args: &[&str]) -> Spawn {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return failed(&format!("could not observe Git: {error}")),
    };
    runtime.block_on(observe(root, args))
}

async fn observe(root: &Path, args: &[&str]) -> Spawn {
    let deadline = Instant::now() + OBSERVATION;
    let mut command = Command::new("git");
    command
        .args(["-c", "core.fsmonitor=false", "-c", "core.askPass="])
        .args(["-c", "credential.interactive=false", "-C"])
        .arg(root)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GCM_INTERACTIVE", "false")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Spawn::Missing,
        Err(error) => return failed(&format!("could not start Git: {error}")),
    };
    let outcome = match timeout_at(deadline, collect(&mut child)).await {
        Ok(Ok(output)) => return Spawn::Output(output),
        Ok(Err(reason)) => reason,
        Err(_) => "Git metadata command or its output did not finish within 10 seconds".into(),
    };
    // Cancelling collection closes both pipes before cleanup. A descendant
    // retaining a pipe cannot turn either collection or cleanup into an
    // unbounded wait. Stop only the child handle this invocation created.
    let reason = match stop(&mut child).await {
        Ok(()) => outcome,
        Err(error) => format!("{outcome}; {error}"),
    };
    failed(&reason)
}

async fn collect(child: &mut Child) -> std::result::Result<Output, String> {
    let stdout = child.stdout.take().ok_or("Git stdout pipe is absent")?;
    let stderr = child.stderr.take().ok_or("Git stderr pipe is absent")?;
    let (status, stdout, stderr) = tokio::try_join!(
        async {
            child
                .wait()
                .await
                .map_err(|error| format!("could not wait for Git: {error}"))
        },
        read(stdout, STDOUT_BOUND, "stdout"),
        read(stderr, STDERR_BOUND, "stderr"),
    )?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

async fn read(
    mut pipe: impl AsyncRead + Unpin,
    bound: usize,
    stream: &str,
) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let count = pipe
            .read(&mut buffer)
            .await
            .map_err(|error| format!("could not read Git {stream}: {error}"))?;
        if count == 0 {
            return Ok(bytes);
        }
        if count > bound.saturating_sub(bytes.len()) {
            return Err(format!(
                "Git {stream} exceeded its {bound}-byte metadata bound"
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

async fn stop(child: &mut Child) -> std::result::Result<(), String> {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return Ok(());
    }
    let process = child.id().map_or_else(
        || "owned Git process".to_owned(),
        |pid| format!("owned Git process {pid}"),
    );
    let stop_error = child.start_kill().err();
    // Exit may have raced the stop request. Only the independent wait decides
    // whether custody settled; a stop error must not skip that readback.
    match timeout(CLEANUP, child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(format!(
            "could not reap {process}: {error}; stop error: {stop_error:?}"
        )),
        Err(_) => Err(format!(
            "{process} has not confirmed exit after its stop request; stop error: {stop_error:?}"
        )),
    }
}

fn failed(reason: &str) -> Spawn {
    Spawn::Unreadable(se_types::SeError::new(se_types::Detail::SourceUnreadable(
        se_types::details::SourceUnreadable {
            subject: "Git repository observation".into(),
            reason: reason.into(),
            next_step: "Restore noninteractive Git access to the selected repository: close any Git sign-in dialog, check that its disk or network location is available, and repair Git if it cannot run. Then retry the original command.".into(),
        },
    )))
}
