//! Control-socket path limits, peer-PID binding, and readiness probing for the
//! shared Codex server.
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

/// Probe whether the login's control socket accepts a connection right now.
/// Returns `Ok(None)` when not listening, or `Ok(Some(peer))` where `peer` is
/// the OS-reported identity of the accepting process when available.
pub(super) async fn probe_served(
    control: &Path,
) -> Result<Option<Option<se_harness::LocalSocketPeer>>> {
    match std::fs::symlink_metadata(control) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(se_core::scope::unreadable(
                "Codex control socket",
                &e.to_string(),
            ));
        }
        Ok(_) => {}
    }
    se_harness::probe_local_socket_peer(control)
        .await
        .map_err(|e| se_core::scope::unreadable("Codex control socket", &e.to_string()))
}

/// Prove that the accepting socket peer matches our verified server identity
/// (PID and Windows process birth) when sandbox verification is required.
/// Non-sandbox / Unix alias launches are left independent of peer identity.
pub(super) fn verify_peer_identity(
    login: &Path,
    peer: Option<se_harness::LocalSocketPeer>,
    expected: &se_proc::ProcessIdentity,
    require_verified: bool,
) -> Result<()> {
    if !require_verified {
        return Ok(());
    }
    let expected_pid = expected.pid.0;
    let expected_birth = match expected.start {
        se_proc::StartIdentity::Windows { creation_filetime } => Some(creation_filetime),
        _ => None,
    };
    match peer {
        Some(actual)
            if actual.pid == expected_pid
                && expected_birth.is_none_or(|b| actual.birth == Some(b)) =>
        {
            Ok(())
        }
        Some(actual) => Err(crate::codex_rpc::incompatible(
            &format!(
                "the Codex control socket for {} is served by PID {} (birth {:?}), not StateEngine's verified server PID {expected_pid} (birth {expected_birth:?})",
                login.display(),
                actual.pid,
                actual.birth,
            ),
            "Stop the other Codex app-server listening on that socket and retry.",
        )),
        None => Err(crate::codex_rpc::incompatible(
            &format!(
                "could not verify that the Codex control socket for {} is served by StateEngine's server PID {expected_pid}",
                login.display()
            ),
            "Restart the Codex app-server for this login or run without windows.sandbox, then retry.",
        )),
    }
}

pub(super) async fn wait_served(
    login: &Path,
    control: &Path,
    expected: &se_proc::ProcessIdentity,
    require_verified: bool,
    deadline: &Deadline,
) -> Result<()> {
    let until = tokio::time::Instant::now() + READY.min(deadline.remaining()?);
    loop {
        if let Some(peer) = probe_served(control).await? {
            return verify_peer_identity(login, peer, expected, require_verified);
        }
        if tokio::time::Instant::now() >= until {
            return Err(crate::codex_rpc::incompatible(
                &format!("the login's app-server did not open {}", control.display()),
                "Check that `codex app-server --listen unix://` starts for this login, then relaunch.",
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
