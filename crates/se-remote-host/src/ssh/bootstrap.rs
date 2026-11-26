//! Pair only after the calling CLI staged and independently verified the image.
use super::command::ssh;
use super::*;
use crate::{LinkSecret, MachineSession, RemoteHostId};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSession {
    pub device: MachineSession,
    pub secret: LinkSecret,
    pub port: u16,
}
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
    // The upload's bytes were hash-verified at publication in this same
    // pairing, and the promotion is a byte-preserving rename of that
    // verified file inside a directory only the destination account can
    // write: re-hashing here would re-prove bytes no network attacker can
    // still reach, so the residual check is identity. The warm path keeps
    // its full digest, re-proving bytes never seen in this run.
    let identity = staging::check(&remote, windows, image.apple);
    let command = if windows {
        let outcome = ssh(destination, identity).await?;
        let (verified, detail) = (outcome.success, &outcome.stdout);
        if !verified {
            return Err(super::command::verification_error(detail));
        }
        acceptance
    } else {
        image_commands::accept(&identity, &acceptance)
    };
    let outcome = ssh(destination, command).await?;
    let bytes = zeroize::Zeroizing::new(outcome.stdout);
    if !outcome.success {
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
    if !matches!(session.device.subject, crate::RemoteSubject::Machine {host} if host == source) {
        return Err(unavailable(
            "remote bootstrap changed the authenticated source machine",
        ));
    }
    Ok((session, invoke("remote __authorize --json")))
}

/// POSIX single-quote escaping: neutralizes every shell metacharacter.
pub fn posix_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// PowerShell single-quote escaping (used inside UTF-16LE `-EncodedCommand`).
pub fn powershell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Build an injection-safe remote `se` invocation for Unix or Windows.
pub fn build_remote_se_command(remote_bin: &str, windows: bool, args: &[&str]) -> String {
    if windows {
        let quoted: Vec<String> = args
            .iter()
            .map(|arg| powershell_single_quote(arg))
            .collect();
        staging::powershell(&format!(
            "& (Join-Path $HOME {}) {}; exit $LASTEXITCODE",
            powershell_single_quote(remote_bin),
            quoted.join(" ")
        ))
    } else {
        let quoted: Vec<String> = args.iter().map(|arg| posix_single_quote(arg)).collect();
        format!("./{remote_bin} {}", quoted.join(" "))
    }
}

/// Run one verified remote `se` command over strict `BatchMode=yes` SSH after
/// confirming the staged executable's account ownership and permissions.
pub async fn run_verified_se_command(
    destination: &str,
    distribution: &std::path::Path,
    args: &[&str],
) -> Result<Vec<u8>> {
    validate_destination(destination)?;
    let img = super::image::describe(destination, distribution).await?;
    let remote_bin = img.remote();
    let windows = img.windows;
    let identity = staging::check(&remote_bin, windows, img.apple);
    let invocation = build_remote_se_command(&remote_bin, windows, args);
    let command = if windows {
        let check = ssh(destination, identity).await?;
        if !check.success {
            return Err(super::command::verification_error(&check.stdout));
        }
        invocation
    } else {
        image_commands::accept(&identity, &invocation)
    };
    let outcome = ssh(destination, command).await?;
    if !outcome.success {
        if outcome
            .stdout
            .starts_with(format!("{}\n", image_commands::VERIFY_FAILED).as_bytes())
        {
            return Err(super::command::verification_error(&outcome.stdout));
        }
        if let Ok(envelope) = serde_json::from_slice::<se_types::ErrorEnvelope>(&outcome.stdout) {
            return Err(envelope.body().clone().with_far_origin().into());
        }
        return Err(refused_setup(&outcome.stdout));
    }
    Ok(outcome.stdout)
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
