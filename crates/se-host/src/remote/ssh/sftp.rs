//! System SFTP uploads avoid the remote login shell's text input boundary.
use super::unavailable;
use se_types::Result;
use std::path::{Path, PathBuf};

pub(super) fn clients() -> Result<(PathBuf, PathBuf)> {
    let path =
        std::env::var_os("PATH").ok_or_else(|| unavailable("SSH client search path is absent"))?;
    let name = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    for directory in std::env::split_paths(&path) {
        let ssh = directory.join(name);
        if !executable(&ssh) {
            continue;
        }
        let sftp = directory.join(if cfg!(windows) { "sftp.exe" } else { "sftp" });
        if !executable(&sftp) {
            return Err(unavailable(
                "the SFTP client beside SSH is absent; install the OpenSSH client tools and retry",
            ));
        }
        return Ok((sftp, ssh));
    }
    Err(unavailable(
        "SSH client is absent; install the OpenSSH client tools and retry",
    ))
}

fn executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[unix]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[not(unix)]
    {
        true
    }
}

pub(super) fn upload_batch(local: &Path, remote: &str) -> Result<String> {
    let local = local
        .to_str()
        .ok_or_else(|| unavailable("native image path is not valid UTF-8"))?;
    // OpenSSH accepts forward slashes on Windows, including drive paths.
    let local = if cfg!(windows) {
        local.replace('\\', "/")
    } else {
        local.to_owned()
    };
    let batch = format!("@put {} {}\n", quote(&local)?, quote(remote)?);
    if batch.len() > 4096 {
        return Err(unavailable("SFTP upload command exceeds its path bound"));
    }
    Ok(batch)
}

fn quote(path: &str) -> Result<String> {
    if path.chars().any(char::is_control) {
        return Err(unavailable("SFTP image path contains a control character"));
    }
    // Quoted SFTP operands suppress glob expansion. Escape the quote and
    // backslash for its batch parser; this text never enters a login shell.
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
