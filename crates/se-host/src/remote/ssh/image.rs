//! Native runtime discovery and hashing shared by staging and pairing.
use super::command::ssh;
use super::*;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub(super) struct Image {
    pub file: tokio::fs::File,
    pub expected: u64,
    pub digest: String,
    pub windows: bool,
    pub apple: bool,
}
impl Image {
    pub fn directory(&self) -> String {
        format!(".stateengine-runtime/{}", self.digest)
    }
    pub fn remote(&self) -> String {
        format!(
            "{}/{}",
            self.directory(),
            if self.windows { "se.exe" } else { "se" }
        )
    }
}
pub(super) async fn describe(destination: &str, distribution: &Path) -> Result<Image> {
    validate_destination(destination)?;
    // Probe fixed commands, not caller-controlled shell fragments. Neither probe
    // mutates the remote host or stops an incompatible incumbent.
    let (unix, platform) = ssh(destination, "uname -sm".into()).await?;
    let platform = String::from_utf8(platform)
        .map_err(|_| unavailable("SSH platform response is not UTF-8"))?;
    let (target, windows) = if unix {
        match platform.trim() {
            "Linux x86_64" => ("x86_64-unknown-linux-gnu", false),
            "Darwin arm64" => ("aarch64-apple-darwin", false),
            "Darwin x86_64" => ("x86_64-apple-darwin", false),
            _ => {
                return Err(unavailable(
                    "remote operating system or architecture is unsupported",
                ));
            }
        }
    } else {
        let (success, platform) = ssh(
            destination,
            staging::powershell(
                "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()",
            ),
        )
        .await?;
        if !success || String::from_utf8_lossy(&platform).trim() != "X64" {
            return Err(unavailable(
                "remote platform discovery failed; check the SSH destination and supported native platform",
            ));
        }
        ("x86_64-pc-windows-msvc", true)
    };
    // A reused host may itself run from an uploaded single-platform cache.
    // Native Owner admission supplies the calling CLI's full distribution.
    let path = image(target, distribution)?;
    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| unavailable("matching native distribution image is unreadable"))?;
    let expected = file
        .metadata()
        .await
        .map_err(|_| unavailable("native image size is unreadable"))?
        .len();
    if expected == 0 || expected > 4 * 1024 * 1024 * 1024 {
        return Err(unavailable(
            "native distribution image exceeds its release size bound",
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = file
            .read(&mut buffer)
            .await
            .map_err(|_| unavailable("native image hash read failed"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > expected {
            return Err(unavailable("native image changed during hash read"));
        }
        digest.update(&buffer[..n]);
    }
    if total != expected {
        return Err(unavailable("native image changed during hash read"));
    }
    let digest = se_types::hex_lower(&digest.finalize());
    let windows_image = windows;
    Ok(Image {
        file,
        expected,
        digest,
        windows: windows_image,
        apple: target.ends_with("apple-darwin"),
    })
}

fn image(target: &str, executable: &Path) -> Result<PathBuf> {
    let local = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        _ => {
            return Err(unavailable(
                "this source platform has no native remote distribution",
            ));
        }
    };
    if target == local {
        return Ok(executable.to_path_buf());
    }
    let name = if target.ends_with("windows-msvc") {
        "se.exe"
    } else {
        "se"
    };
    let companion = executable
        .parent()
        .ok_or_else(|| unavailable("native image parent absent"))?
        .join("remote-images")
        .join(target)
        .join(name);
    match companion.try_exists() {
        Ok(true) => Ok(companion),
        Ok(false) => Err(unavailable(
            "the matching native remote image is absent from this distribution",
        )),
        Err(_) => Err(unavailable(
            "the matching native remote image cannot be inspected",
        )),
    }
}
