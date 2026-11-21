//! One verified HTTP connection per control operation after a native restart.
use super::{control_proof, unreadable};
use crate::Deadline;
use base64::Engine;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, body::Bytes, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use se_types::{Result, Secret};
use serde::Deserialize;
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc};
use zeroize::Zeroizing;

pub(super) struct RestartProof {
    pub capability: Arc<Secret>,
    pub restart: [u8; 32],
}

fn failed() -> se_types::SeError {
    unreadable(
        "SE Code control proof",
        "the replacement service did not prove the restart capability; retry its original endpoint",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofReply {
    mac: String,
}

fn challenge_request(
    proof: &RestartProof,
    challenge: &[u8; 32],
    authority: &str,
) -> Result<Request<Full<Bytes>>> {
    let body = serde_json::to_vec(
        &serde_json::json!({"restart_key":se_types::hex_lower(&proof.restart),
        "challenge":se_types::hex_lower(challenge)}),
    )
    .map_err(|_| failed())?;
    Request::builder()
        .method(Method::POST)
        .uri("/api/stateengine/rebind/challenge")
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| failed())
}

async fn exchange(
    endpoint: &reqwest::Url,
    proof: &RestartProof,
    credential: Option<&Secret>,
    operation: Option<(Method, &reqwest::Url, Option<&Value>)>,
    deadline: &Deadline,
) -> Result<Value> {
    let host = endpoint
        .host_str()
        .ok_or_else(failed)?
        .trim_matches(['[', ']']);
    let ip = host.parse().map_err(|_| failed())?;
    let address = SocketAddr::new(ip, endpoint.port_or_known_default().ok_or_else(failed)?);
    let authority = address.to_string();
    let until = tokio::time::Instant::from_std(deadline.at());
    let stream = tokio::time::timeout_at(until, tokio::net::TcpStream::connect(address))
        .await
        .map_err(|_| failed())?
        .map_err(|_| failed())?;
    let (mut sender, connection) =
        tokio::time::timeout_at(until, http1::handshake(TokioIo::new(stream)))
            .await
            .map_err(|_| failed())?
            .map_err(|_| failed())?;
    let mut driver = Driver(tokio::spawn(connection));
    let result = tokio::time::timeout_at(until, async {
        let mut challenge = [0u8; 32];
        se_proc::fill_entropy(&mut challenge).map_err(|_| failed())?;
        let request = challenge_request(proof, &challenge, &authority)?;
        let response = sender.send_request(request).await.map_err(|_| failed())?;
        if !response.status().is_success() {
            return Err(failed());
        }
        let body = Limited::new(response.into_body(), 4096)
            .collect()
            .await
            .map_err(|_| failed())?
            .to_bytes();
        let response: ProofReply = serde_json::from_slice(&body).map_err(|_| failed())?;
        control_proof::verify(&proof.capability, &proof.restart, &challenge, &response.mac)?;
        let Some((method, url, body)) = operation else {
            return Ok(Value::Null);
        };
        let credential = credential.ok_or_else(failed)?;
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(credential.expose()));
        let authorization_text = Zeroizing::new(format!("Basic {}", encoded.as_str()));
        let mut authorization =
            header::HeaderValue::from_str(&authorization_text).map_err(|_| failed())?;
        authorization.set_sensitive(true);
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let payload = match body {
            Some(value) => serde_json::to_vec(value).map_err(|_| failed())?,
            None => Vec::new(),
        };
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, &authority)
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(payload)))
            .map_err(|_| failed())?;
        let response = sender.send_request(request).await.map_err(|_| failed())?;
        let status = response.status();
        let limit = if status.is_success() {
            8 * 1024 * 1024
        } else {
            65536
        };
        let body = Limited::new(response.into_body(), limit)
            .collect()
            .await
            .map_err(|_| failed())?
            .to_bytes();
        if !status.is_success() {
            return Err(unreadable(
                "SE Code authenticated control",
                format!("HTTP {status}; retain the original operation for readback"),
            ));
        }
        if status == StatusCode::NO_CONTENT && body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&body)
            .map_err(|_| unreadable("SE Code control JSON", "the response was not valid JSON"))
    })
    .await
    .map_err(|_| failed())
    .and_then(|value| value);
    drop(sender);
    driver.0.abort();
    let _ = (&mut driver.0).await;
    result
}

struct Driver(tokio::task::JoinHandle<std::result::Result<(), hyper::Error>>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn check(
    endpoint: &reqwest::Url,
    proof: &RestartProof,
    deadline: &Deadline,
) -> Result<()> {
    exchange(endpoint, proof, None, None, deadline).await?;
    Ok(())
}

pub(super) async fn request(
    endpoint: &reqwest::Url,
    proof: &RestartProof,
    credential: &Secret,
    method: Method,
    url: &reqwest::Url,
    body: Option<&Value>,
    deadline: &Deadline,
) -> Result<Value> {
    exchange(
        endpoint,
        proof,
        Some(credential),
        Some((method, url, body)),
        deadline,
    )
    .await
}

#[cfg(test)]
#[path = "../../tests/support/rebind_control.rs"]
mod tests;
