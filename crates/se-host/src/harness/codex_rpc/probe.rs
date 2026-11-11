//! Short-lived version probe only; owned provider launches still pass through
//! the native process arena and the coordinator's three durable barriers.
use super::incompatible;
use crate::harness::codex_input::provider_environment;
use crate::{CODEX_MINIMUM_VERSION, HarnessKind, ProviderVersion};
use se_types::{NativePath, Result};
use std::{
    future::{Future, poll_fn},
    path::Path,
    pin::pin,
    process::{ExitStatus, Stdio},
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, process::Command};

const OUTPUT_PER_STREAM: u64 = 8 * 1024;

async fn output(stream: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream
        .take(OUTPUT_PER_STREAM + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| se_core::scope::unreadable("Codex version output", &e.to_string()))?;
    if bytes.len() as u64 > OUTPUT_PER_STREAM {
        return Err(incompatible(
            "version probe exceeded its 16-KiB output bound",
            "Use a stock supported Codex executable.",
        ));
    }
    Ok(bytes)
}

/// Bound both pipes while the child is running: a full pipe cannot deadlock
/// the probe. Timeout/error kills only this direct child and awaits its exit.
pub async fn probe(command: &Path, budget: Duration) -> Result<ProviderVersion> {
    if !command.is_absolute() {
        return Err(incompatible(
            "probe executable is not absolute",
            "Resolve the configured executable before probing.",
        ));
    }
    let budget = budget.min(Duration::from_secs(5));
    if budget.is_zero() {
        return Err(incompatible(
            "probe deadline expired",
            "Retry with an unexpired launch deadline.",
        ));
    }
    let end = Instant::now() + budget;
    // Reserve part of the same five-second ceiling for killing and reaping.
    let run_end = end - (budget / 10).min(Duration::from_millis(500));
    let mut child = Command::new(command)
        .arg("--version")
        .env_clear()
        .envs(provider_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| se_core::scope::unreadable("Codex executable probe", &e.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| incompatible("probe stdout is absent", "Retry the executable probe."))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| incompatible("probe stderr is absent", "Retry the executable probe."))?;
    let read = {
        let mut stdout = pin!(output(stdout));
        let mut stderr = pin!(output(stderr));
        let mut exit = pin!(child.wait());
        let mut out = None;
        let mut err = None;
        let mut status: Option<ExitStatus> = None;
        let together = poll_fn(|cx| {
            if out.is_none()
                && let Poll::Ready(value) = stdout.as_mut().poll(cx)
            {
                out = Some(value?);
            }
            if err.is_none()
                && let Poll::Ready(value) = stderr.as_mut().poll(cx)
            {
                err = Some(value?);
            }
            if status.is_none()
                && let Poll::Ready(value) = exit.as_mut().poll(cx)
            {
                status =
                    Some(value.map_err(|e| {
                        se_core::scope::unreadable("Codex probe exit", &e.to_string())
                    })?);
            }
            match (out.take(), err.take(), status.take()) {
                (Some(out), Some(err), Some(status)) => Poll::Ready(Ok((out, err, status))),
                (a, b, c) => {
                    out = a;
                    err = b;
                    status = c;
                    Poll::Pending
                }
            }
        });
        tokio::time::timeout_at(tokio::time::Instant::from_std(run_end), together).await
    };
    let measured = match read {
        Ok(result) => result,
        Err(_) => Err(incompatible(
            "version probe exceeded its five-second deadline",
            "Update or repair the configured Codex executable.",
        )),
    };
    let measured = match measured {
        Ok(value) => value,
        Err(error) => {
            // start_kill is idempotent for this retained direct child. Keep the
            // original probe error unless cleanup itself cannot be proved.
            let _ = child.start_kill();
            if !matches!(
                tokio::time::timeout_at(tokio::time::Instant::from_std(end), child.wait()).await,
                Ok(Ok(_))
            ) {
                return Err(incompatible(
                    "version probe failed and its child exit is unproved",
                    "Reconcile the exact probe child before retrying.",
                ));
            }
            return Err(error);
        }
    };
    if !measured.2.success() {
        return Err(incompatible(
            "the version probe exited unsuccessfully",
            "Repair the configured Codex executable.",
        ));
    }
    let text = std::str::from_utf8(&measured.0).map_err(|_| {
        incompatible(
            "version output is not UTF-8",
            "Use a stock supported Codex executable.",
        )
    })?;
    let version = text.trim().strip_prefix("codex-cli ").ok_or_else(|| {
        incompatible(
            "version output does not identify codex-cli",
            "Use a stock supported Codex executable.",
        )
    })?;
    let parts = version
        .split('.')
        .map(str::parse::<u16>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| {
            incompatible(
                "unrecognized Codex version",
                "Use a stable supported Codex release.",
            )
        })?;
    if parts.len() != 3 || (parts[0], parts[1], parts[2]) < CODEX_MINIMUM_VERSION {
        return Err(incompatible(
            "Codex is below the required app-server version floor",
            "Install Codex 0.152.0 or newer.",
        ));
    }
    Ok(ProviderVersion {
        kind: HarnessKind::CodexAppServer,
        executable: NativePath::from_local(command.to_owned())?,
        version: version.into(),
        protocol: "app-server/stdio-json-lines".into(),
    })
}
