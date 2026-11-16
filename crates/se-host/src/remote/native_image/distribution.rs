//! Native runtime discovery and hashing shared by staging and pairing.
use super::staging;
use crate::remote::{channel::unavailable, ssh::command::ssh};
use se_remote::ssh::validate_destination;
use se_types::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub(in crate::remote) struct Image {
    pub path: PathBuf,
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
pub(in crate::remote) async fn describe(destination: &str, distribution: &Path) -> Result<Image> {
    validate_destination(destination)?;
    // Probe fixed commands, not caller-controlled shell fragments. Neither probe
    // mutates the remote host or stops an incompatible incumbent.
    let (unix, platform) = ssh(destination, "uname -sm".into()).await?;
    let platform = String::from_utf8(platform)
        .map_err(|_| unavailable("SSH platform response is not UTF-8"))?;
    let uname = platform.trim();
    let (target, windows) = match (unix, uname) {
        (true, "Linux x86_64") => ("x86_64-unknown-linux-gnu", false),
        (true, "Darwin arm64") => ("aarch64-apple-darwin", false),
        (true, "Darwin x86_64") => ("x86_64-apple-darwin", false),
        // A failed uname exit, or a compatibility responder that names no
        // supported Unix target (Git for Windows' uname answers
        // "MSYS_NT-10.0-26100 x86_64"), is verified through the Windows
        // architecture probe before it is rejected.
        _ => {
            let (success, probe) = ssh(
                destination,
                staging::powershell(
                    "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()",
                ),
            )
            .await?;
            if success && String::from_utf8_lossy(&probe).trim() == "X64" {
                ("x86_64-pc-windows-msvc", true)
            } else if unix {
                // uname identified a system that is neither a supported Unix
                // target nor a Windows x64 host; reject it by name.
                let named: String = uname.chars().take(60).collect();
                return Err(unavailable(&format!(
                    "remote operating system or architecture is unsupported: {named}"
                )));
            } else {
                return Err(unavailable(
                    "remote platform discovery failed; check the SSH destination and supported native platform",
                ));
            }
        }
    };
    // A reused host may itself run from an uploaded single-platform cache.
    // Native Owner admission supplies the calling CLI's full distribution.
    let path = std::path::absolute(image(target, distribution)?)
        .map_err(|_| unavailable("native distribution image path is unreadable"))?;
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
        path,
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
