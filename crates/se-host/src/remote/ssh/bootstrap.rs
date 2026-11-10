//! Native image staging and protected bootstrap over an authenticated SSH login.
use super::*;
use crate::remote::{BootstrapSession, RemoteHostId};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

async fn output(program: &str, arguments: &[String]) -> Result<(bool, Vec<u8>)> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| unavailable("cannot start the system SSH file-transfer client"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| unavailable("SSH output pipe absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| unavailable("SSH error pipe absent"))?;
    let result = timeout(Duration::from_secs(25), async {
        let mut bytes = Vec::new();
        let mut errors = Vec::new();
        let mut stdout = stdout.take(65537);
        let mut stderr = stderr.take(4097);
        tokio::try_join!(
            stdout.read_to_end(&mut bytes),
            stderr.read_to_end(&mut errors)
        )
        .map_err(|_| unavailable("SSH output could not be read"))?;
        if bytes.len() > 65536 || errors.len() > 4096 {
            return Err(unavailable(
                "SSH output exceeded its bounded bootstrap response",
            ));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| unavailable("SSH completion could not be observed"))?;
        Ok((status.success(), bytes))
    })
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        other => {
            if child
                .try_wait()
                .map_err(|_| unavailable("SSH custody unreadable"))?
                .is_none()
            {
                child
                    .start_kill()
                    .map_err(|_| unavailable("cannot close owned SSH bootstrap"))?;
            }
            child
                .wait()
                .await
                .map_err(|_| unavailable("cannot join SSH bootstrap"))?;
            match other {
                Ok(Err(error)) => Err(error),
                _ => Err(unavailable("SSH bootstrap exceeded 25 seconds")),
            }
        }
    }
}
async fn ssh(destination: &str, command: String) -> Result<(bool, Vec<u8>)> {
    validate_destination(destination)?;
    output(
        "ssh",
        &[
            "-T".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            destination.into(),
            command,
        ],
    )
    .await
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

/// A refused bootstrap answer carries the peer's own error body: mark it as
/// far-origin so the renderer escapes its terminal text. An unstructured
/// refusal stays a local error.
fn refused_setup(bytes: &[u8]) -> se_types::SeError {
    if let Ok(body) = serde_json::from_slice::<se_types::ErrorBody>(bytes) {
        return body.with_far_origin().into();
    }
    unavailable(
        "remote bootstrap refused without a structured reason; the existing host was preserved",
    )
}
pub async fn connect(
    destination: &str,
    source: RemoteHostId,
    distribution: PathBuf,
) -> Result<(BootstrapSession, String)> {
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
    let path = image(target, &distribution)?;
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
    let mut buffer = [0u8; 65536];
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
    // Staging must not precreate the protected data home with inherited ACLs.
    let directory = format!(".stateengine-runtime/{digest}");
    let remote = format!("{directory}/{}", if windows { "se.exe" } else { "se" });
    let apple = target.ends_with("apple-darwin");
    if !ssh(destination, staging::prepare(&directory, windows, apple))
        .await?
        .0
    {
        return Err(unavailable(
            "remote runtime cache ownership or permissions refused; preserve unsafe paths and restore an account-owned directory without foreign write access",
        ));
    }
    let verify = staging::verify(&remote, &digest, windows, apple);
    if !ssh(destination, verify.clone()).await?.0 {
        let upload = format!(
            "{remote}.upload-{}",
            se_types::hex_lower(&crate::remote::session::entropy::<16>()?)
        );
        let local = path
            .to_str()
            .ok_or_else(|| unavailable("native image path is not valid text for file transfer"))?;
        let transfer = output(
            "scp",
            &[
                "-q".into(),
                "-B".into(),
                local.into(),
                format!("{destination}:{upload}"),
            ],
        )
        .await;
        let result=async {
            if !transfer?.0 || !ssh(destination,staging::verify(&upload,&digest,windows,apple)).await?.0 {
                return Err(unavailable("native image transfer or independent hash readback failed"));
            }
            // A concurrent uploader may have published the exact same image.
            // Never overwrite a present path, including an incomplete old one.
            let _published=ssh(destination,staging::publish(&upload,&remote,windows)).await?;
            if !ssh(destination,verify).await?.0 {return Err(unavailable("native image publication refused; preserve the incumbent cache file and restore an account-owned matching distribution image without foreign write access"));}
            Ok(())
        }.await;
        let cleanup = ssh(destination, staging::remove(&upload, windows)).await;
        match (result, cleanup) {
            (Err(error), _) => return Err(error),
            (Ok(()), Ok((true, _))) => (),
            (Ok(()), _) => {
                return Err(unavailable(
                    "native image verified, but its owned upload cleanup is incomplete; retry setup with the original machine name",
                ));
            }
        }
    }
    let invoke = |arguments: &str| {
        if windows {
            staging::powershell(&format!(
                "& (Join-Path $HOME '{remote}') {arguments}; exit $LASTEXITCODE"
            ))
        } else {
            format!("./{remote} {arguments}")
        }
    };
    let (success, bytes) = ssh(
        destination,
        invoke(&format!(
            "remote __accept --source-host {} --json",
            source.0.hex()
        )),
    )
    .await?;
    let bytes = zeroize::Zeroizing::new(bytes);
    if !success {
        return Err(refused_setup(&bytes));
    }
    #[derive(serde::Deserialize)]
    struct Envelope {
        schema: String,
        value: BootstrapSession,
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)
        .map_err(|_| unavailable("remote bootstrap session or protocol is incompatible"))?;
    if envelope.schema != "stateengine.remote-control/v1" {
        return Err(unavailable("remote bootstrap protocol is incompatible"));
    }
    let session = envelope.value;
    if !matches!(session.device.subject, crate::remote::RemoteSubject::Machine {host} if host == source)
    {
        return Err(unavailable(
            "remote bootstrap changed the authenticated source machine",
        ));
    }
    Ok((session, invoke("remote __authorize --json")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_setup_marks_the_peer_body_far_origin() {
        let bytes = br#"{"code":"listener-unavailable","detail":{"subject":"the socket","reason":"peer says \u001b[31mbad","next_step":"reconnect \u001b[1mnow"}}"#;
        let error = refused_setup(bytes);
        assert!(error.body.far(), "peer body must be marked far-origin");
    }

    #[test]
    fn refused_setup_without_a_structured_body_stays_local() {
        let error = refused_setup(b"no structured body");
        assert!(!error.body.far());
    }
}
