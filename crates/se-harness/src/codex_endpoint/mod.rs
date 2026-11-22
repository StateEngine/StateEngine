//! Where a Codex agent's forwarder listens: a private local socket in a
//! per-launch directory, chosen to fit the platform's socket path limit, and
//! on Windows the custody of that endpoint (Unix custody stays with the launch
//! record it extends).
use se_types::{Result, SessionId};
use std::path::{Path, PathBuf};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{hold_short_root, prepare, record, recover, retire};

fn native(error: impl std::fmt::Display) -> se_types::SeError {
    se_core::scope::unreadable("Codex native custody", &error.to_string())
}

/// The listen path for a launch whose own directory is `launch`. Unix falls
/// back to the private runtime root, then the short provider root.
#[cfg(unix)]
pub(crate) fn socket_path(
    launch: PathBuf,
    socket_root: &Path,
    _state_home: &Path,
    session: &SessionId,
) -> Result<Option<PathBuf>> {
    use std::os::unix::ffi::OsStrExt;
    let preferred = launch.join("cx/s");
    let selected = if preferred.as_os_str().as_bytes().len() < 100 {
        preferred
    } else {
        let launch = se_proc::session_launch_id(session).map_err(native)?;
        let name = format!("se-cx-{}", launch.as_str().trim_start_matches("lch_"));
        let requested = socket_root.join(&name).join("s");
        if requested.as_os_str().as_bytes().len() < 100 {
            requested
        } else {
            se_proc::native_ipc::UnixSocketPaths::short_provider_root()
                .join(&name)
                .join("s")
        }
    };
    if !selected.is_absolute() || selected.as_os_str().as_bytes().len() >= 100 {
        return Err(crate::harness::codex_rpc::incompatible(
            "no protected Unix socket path fits the provider limit",
            "Select a shorter private runtime/temp location.",
        ));
    }
    Ok(Some(selected))
}

/// The listen path for a launch whose own directory is `launch`. Windows
/// falls back to a short private directory under the data home named by the
/// launch.
#[cfg(windows)]
pub(crate) fn socket_path(
    launch: PathBuf,
    _socket_root: &Path,
    state_home: &Path,
    session: &SessionId,
) -> Result<Option<PathBuf>> {
    use sha2::{Digest, Sha256};
    /// The longest local socket path Windows accepts.
    const LIMIT: usize = 107;
    let preferred = launch.join("cx").join("s");
    let selected = if preferred.as_os_str().as_encoded_bytes().len() <= LIMIT {
        preferred
    } else {
        let launch = se_proc::session_launch_id(session).map_err(native)?;
        let name = se_types::hex_lower(&Sha256::digest(launch.as_str().as_bytes()));
        state_home.join("cx").join(&name[..16]).join("s")
    };
    if selected.as_os_str().as_encoded_bytes().len() > LIMIT {
        return Err(crate::harness::codex_rpc::incompatible(
            "the private local socket path is longer than Windows allows",
            "Move the StateEngine data home to a shorter folder and relaunch.",
        ));
    }
    Ok(Some(selected))
}

/// No private local socket on other platforms.
#[cfg(not(any(unix, windows)))]
pub(crate) fn socket_path(
    _launch: PathBuf,
    _socket_root: &Path,
    _state_home: &Path,
    _session: &SessionId,
) -> Result<Option<PathBuf>> {
    Ok(None)
}
