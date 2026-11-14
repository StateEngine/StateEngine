//! Git output uses readiness observation rather than blocking reader threads.
#[cfg(windows)]
#[path = "pipe/windows.rs"]
mod windows;
#[cfg(windows)]
pub(super) use windows::{stderr, stdout};

#[cfg(not(windows))]
pub(super) fn stdout(
    pipe: tokio::process::ChildStdout,
) -> std::io::Result<tokio::process::ChildStdout> {
    Ok(pipe)
}

#[cfg(not(windows))]
pub(super) fn stderr(
    pipe: tokio::process::ChildStderr,
) -> std::io::Result<tokio::process::ChildStderr> {
    Ok(pipe)
}
