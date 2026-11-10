//! Application authorization stays on SSH; a forwarded socket carries no secret.
use crate::remote::{LinkSecret, RemoteHello, RemoteHostId, RemoteReady};
use se_types::ErrorBody;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub channel: [u8; 32],
    pub hello: RemoteHello,
    pub credential: LinkSecret,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResult {
    pub channel: [u8; 32],
    pub result: std::result::Result<RemoteReady, ErrorBody>,
}

/// Both requests use the saved native command over the authenticated SSH pipe.
/// A start restores the existing listener policy; it never creates a grant.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Request {
    Authorize(Authorization),
    Start(StartRequest),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub start: RemoteHostId,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartResult {
    pub host: RemoteHostId,
}

pub(super) async fn restart(config: &super::ForwardConfig) -> se_types::Result<()> {
    let request = Request::Start(StartRequest { start: config.host });
    let bytes = encoded(&request)?;
    let response = exchange(config, bytes, std::time::Duration::from_secs(25)).await?;
    let result: StartResult = serde_json::from_slice(&response)
        .map_err(|_| super::unavailable("SSH host restart response is malformed"))?;
    if result.host != config.host {
        return Err(super::unavailable(
            "SSH host restart changed the saved machine identity",
        ));
    }
    Ok(())
}
fn encoded(request: &Request) -> se_types::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(request)
            .map_err(|_| super::unavailable("SSH request could not be encoded"))?,
    );
    bytes.push(b'\n');
    if bytes.len() > 32768 {
        return Err(super::unavailable("SSH request exceeded its input bound"));
    }
    Ok(bytes)
}

/// Credentials travel only through this owned SSH child's private stdin. It
/// exits after one native authorization; no SE control helper remains resident.
pub(super) async fn run(
    config: &super::ForwardConfig,
    authorization: Authorization,
) -> se_types::Result<RemoteReady> {
    let channel = authorization.channel;
    let bytes = encoded(&Request::Authorize(authorization))?;
    let response = exchange(config, bytes, std::time::Duration::from_secs(10)).await?;
    let response: AuthorizationResult = serde_json::from_slice(&response)
        .map_err(|_| super::unavailable("SSH authorization response is malformed"))?;
    if response.channel != channel {
        return Err(super::unavailable(
            "SSH authorization changed the requested channel",
        ));
    }
    response.result.map_err(Into::into)
}
async fn exchange(
    config: &super::ForwardConfig,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    deadline: std::time::Duration,
) -> se_types::Result<Vec<u8>> {
    use super::{Command, Stdio, unavailable};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut child = Command::new("ssh")
        .args(["-T", "-o", "BatchMode=yes"])
        .arg(&config.destination)
        .arg(&config.command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| unavailable("cannot start protected SSH authorization"))?;
    let exchange = tokio::time::timeout(deadline, async {
        let mut input = child.stdin.take()
            .ok_or_else(|| unavailable("SSH authorization input pipe is absent"))?;
        input.write_all(&bytes).await
            .map_err(|_| unavailable("SSH authorization write failed"))?;
        input.shutdown().await
            .map_err(|_| unavailable("SSH authorization input did not close"))?;
        drop(input);
        let mut output = child.stdout.take()
            .ok_or_else(|| unavailable("SSH authorization output pipe is absent"))?.take(32769);
        let mut errors = child.stderr.take()
            .ok_or_else(|| unavailable("SSH authorization error pipe is absent"))?.take(4097);
        let mut response = Vec::new();
        let mut diagnostics = Vec::new();
        tokio::try_join!(output.read_to_end(&mut response), errors.read_to_end(&mut diagnostics))
            .map_err(|_| unavailable("SSH authorization response could not be read"))?;
        if response.len() > 32768 || diagnostics.len() > 4096 {
            return Err(unavailable("SSH authorization exceeded its output bound"));
        }
        let status = child.wait().await
            .map_err(|_| unavailable("SSH authorization exit could not be observed"))?;
        if !status.success() {
            return Err(unavailable("SSH authorization refused; check the saved SSH destination and native owner access"));
        }
        Ok(response)
    }).await;
    match exchange {
        Ok(Ok(response)) => Ok(response),
        result => {
            if child
                .try_wait()
                .map_err(|_| unavailable("SSH authorization custody is unreadable"))?
                .is_none()
            {
                child
                    .start_kill()
                    .map_err(|_| unavailable("cannot stop owned SSH authorization"))?;
            }
            child
                .wait()
                .await
                .map_err(|_| unavailable("cannot join SSH authorization"))?;
            match result {
                Ok(Err(error)) => Err(error),
                _ => Err(unavailable(
                    "SSH native command exceeded its startup or authorization deadline",
                )),
            }
        }
    }
}
