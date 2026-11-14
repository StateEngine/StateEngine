//! Pair only after the calling CLI staged and independently verified the image.
use super::command::ssh;
use super::*;
use crate::remote::{BootstrapSession, RemoteHostId};
use std::path::PathBuf;

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
    let image = super::image::describe(destination, &distribution).await?;
    let remote = image.remote();
    let windows = image.windows;
    let invoke = |arguments: &str| {
        if windows {
            staging::powershell(&format!(
                "& (Join-Path $HOME '{remote}') {arguments}; exit $LASTEXITCODE"
            ))
        } else {
            format!("./{remote} {arguments}")
        }
    };
    let acceptance = invoke(&format!(
        "remote __accept --source-host {} --json",
        source.0.hex()
    ));
    let verification = staging::verify(&remote, &image.digest, windows, image.apple);
    let command = if windows {
        let (verified, detail) = ssh(destination, verification).await?;
        if !verified {
            return Err(super::command::verification_error(&detail));
        }
        acceptance
    } else {
        image_commands::accept(&verification, &acceptance)
    };
    let (success, bytes) = ssh(destination, command).await?;
    let bytes = zeroize::Zeroizing::new(bytes);
    if !success {
        if bytes.starts_with(format!("{}\n", image_commands::VERIFY_FAILED).as_bytes()) {
            return Err(super::command::verification_error(&bytes));
        }
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
