//! Control-socket path limits and readiness probing for the shared Codex server.
use super::READY;
use crate::client::lease::Deadline;
use se_types::Result;
use std::{path::Path, time::Duration};

/// A local socket address holds a short path: 104 bytes with its terminator on
/// macOS, 108 elsewhere. The stock server refuses a longer one too.
pub(super) fn socket_fits(control: &Path) -> Result<()> {
    const LIMIT: usize = if cfg!(target_os = "macos") { 103 } else { 107 };
    let length = control.as_os_str().as_encoded_bytes().len();
    if length > LIMIT {
        return Err(crate::codex_rpc::incompatible(
            &format!(
                "the Codex login's control socket path is {length} bytes, longer than the {LIMIT} a local socket allows ({})",
                control.display()
            ),
            "Set CODEX_HOME to a shorter folder (for example one directly under your home folder), sign in to Codex there, and relaunch.",
        ));
    }
    Ok(())
}

/// Whether the login's control socket accepts a connection right now.
pub(super) async fn served(control: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(control) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(se_core::scope::unreadable(
                "Codex control socket",
                &e.to_string(),
            ));
        }
        Ok(_) => {}
    }
    #[cfg(unix)]
    let attempt = tokio::net::UnixStream::connect(control).await.map(drop);
    #[cfg(windows)]
    let attempt = {
        let control = control.to_owned();
        tokio::task::spawn_blocking(move || uds_windows::UnixStream::connect(control).map(drop))
            .await
            .map_err(|e| crate::process::error("Codex control socket", e))?
    };
    match attempt {
        Ok(()) => Ok(true),
        // A socket file nobody listens on: refused, or on Windows WSAENETDOWN.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) || (cfg!(windows) && e.raw_os_error() == Some(10050)) =>
        {
            Ok(false)
        }
        Err(e) => Err(se_core::scope::unreadable(
            "Codex control socket",
            &e.to_string(),
        )),
    }
}

pub(super) async fn wait_served(control: &Path, deadline: &Deadline) -> Result<()> {
    let until = tokio::time::Instant::now() + READY.min(deadline.remaining()?);
    while !served(control).await? {
        if tokio::time::Instant::now() >= until {
            return Err(crate::codex_rpc::incompatible(
                &format!("the login's app-server did not open {}", control.display()),
                "Check that `codex app-server --listen unix://` starts for this login, then relaunch.",
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}
