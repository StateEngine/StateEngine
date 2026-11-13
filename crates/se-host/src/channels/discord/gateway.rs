//! The socket keeps heartbeats independent of host mail/output work. A committed
//! dispatch checkpoint, rather than the heartbeat sequence, is used for Resume.
use super::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use tokio::{sync::mpsc, time::Instant};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{Role, WebSocketConfig},
    },
};

type Socket = WebSocketStream<reqwest::Upgraded>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resume {
    session: String,
    gateway: String,
    seq: u64,
}
impl Resume {
    fn decode(cursor: &ReceiveCursor) -> ChannelResult<Self> {
        let value: Self = serde_json::from_str(cursor.as_str()).map_err(|_| Error::InvalidInput)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> ChannelResult<()> {
        if self.session.is_empty()
            || self.session.len() > 128
            || self.session.chars().any(char::is_control)
            || self.seq > i64::MAX as u64
        {
            return Err(Error::ProviderProtocol);
        }
        gateway_url(&self.gateway)?;
        Ok(())
    }
    fn cursor(&self) -> ChannelResult<ReceiveCursor> {
        self.validate()?;
        ReceiveCursor::new(serde_json::to_string(self).map_err(|_| Error::ProviderProtocol)?)
            .map_err(|_| Error::ProviderProtocol)
    }
}
struct Dispatch {
    update: ExternalId,
    cursor: ReceiveCursor,
    message: Option<Value>,
}
pub(super) struct Receiver {
    transport: Arc<Discord>,
    resume: Option<Resume>,
    rows: Option<mpsc::Receiver<ChannelResult<Dispatch>>>,
    direct: HashSet<(ExternalId, ExternalId)>,
    task: Option<tokio::task::JoinHandle<()>>,
    pending: Option<ReceiveCursor>,
    current: Option<Dispatch>,
    established: bool,
}
impl Receiver {
    pub fn new(transport: Arc<Discord>, cursor: Option<ReceiveCursor>) -> ChannelResult<Self> {
        let resume = cursor.as_ref().map(Resume::decode).transpose()?;
        Ok(Self {
            transport,
            resume,
            rows: None,
            task: None,
            pending: None,
            current: None,
            established: false,
            direct: HashSet::new(),
        })
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl ChannelReceiver for Receiver {
    fn next<'a>(
        &'a mut self,
        token: &'a se_types::Secret,
    ) -> TransportFuture<'a, Option<Incoming>> {
        Box::pin(async move {
            if self.pending.is_some() {
                return Err(Error::InvalidInput);
            }
            if self.task.is_none() {
                let token = se_types::Secret::new(token.expose().to_vec())
                    .map_err(|_| Error::InvalidToken)?;
                let transport = self.transport.clone();
                let resume = self.resume.take();
                let (send, receive) = mpsc::channel(16);
                self.rows = Some(receive);
                self.task = Some(tokio::spawn(async move {
                    if let Err(error) = run(transport, &token, resume, &send).await {
                        let _ = send.send(Err(error)).await;
                    }
                }));
            }
            if self.current.is_none() {
                let rows = self.rows.as_mut().ok_or(Error::ReceiverNotRunning)?;
                let row = tokio::select! {
                    row = rows.recv() => row.ok_or(Error::ProviderUnreachable)??,
                    // Heartbeats remain active while an authenticated stream is
                    // idle. Yield before the host's receive deadline, without
                    // inventing a dispatch or advancing the saved cursor.
                    _ = tokio::time::sleep(Duration::from_secs(20)), if self.established => return Ok(None),
                };
                self.current = Some(row);
            }
            let row = self.current.as_ref().ok_or(Error::ReceiverNotRunning)?;
            let content = match &row.message {
                Some(value) => {
                    super::message::normalize(&self.transport, token, value, &mut self.direct)
                        .await?
                }
                None => IncomingContent::Unsupported,
            };
            // Keep the dispatch across cancellation of its identity lookup.
            let row = self.current.take().ok_or(Error::ReceiverNotRunning)?;
            self.established = true;
            self.pending = Some(row.cursor.clone());
            Ok(Some(Incoming {
                update: row.update,
                cursor: row.cursor,
                content,
            }))
        })
    }
    fn ack(&mut self, cursor: &ReceiveCursor) -> ChannelResult<()> {
        if self.pending.as_ref() != Some(cursor) {
            return Err(Error::InvalidInput);
        }
        self.pending = None;
        Ok(())
    }
}
fn gateway_url(raw: &str) -> ChannelResult<reqwest::Url> {
    if raw.len() > 1024 {
        return Err(Error::ProviderProtocol);
    }
    let mut url = reqwest::Url::parse(raw).map_err(|_| Error::ProviderProtocol)?;
    let host = url.host_str().ok_or(Error::ProviderProtocol)?;
    if url.scheme() != "wss"
        || !(host == "gateway.discord.gg" || host.ends_with(".discord.gg"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::ProviderProtocol);
    }
    url.set_scheme("https")
        .map_err(|_| Error::ProviderProtocol)?;
    url.set_query(Some("v=10&encoding=json"));
    Ok(url)
}
async fn socket(transport: &Discord, gateway: &str) -> ChannelResult<Socket> {
    use tokio_tungstenite::tungstenite::handshake::{client::generate_key, derive_accept_key};
    let key = generate_key();
    let response = transport
        .client
        .get(gateway_url(gateway)?)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_KEY, &key)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| Error::ProviderUnreachable)?;
    if response.status().as_u16() != 101
        || response
            .headers()
            .get(header::SEC_WEBSOCKET_ACCEPT)
            .and_then(|v| v.to_str().ok())
            != Some(derive_accept_key(key.as_bytes()).as_str())
    {
        return Err(Error::ProviderProtocol);
    }
    let stream = response
        .upgrade()
        .await
        .map_err(|_| Error::ProviderUnreachable)?;
    Ok(WebSocketStream::from_raw_socket(
        stream,
        Role::Client,
        Some(
            WebSocketConfig::default()
                .max_message_size(Some(256 * 1024))
                .max_frame_size(Some(256 * 1024)),
        ),
    )
    .await)
}
async fn send(socket: &mut Socket, value: Value) -> ChannelResult<()> {
    tokio::time::timeout(
        Duration::from_secs(10),
        socket.send(Message::Text(value.to_string().into())),
    )
    .await
    .map_err(|_| Error::ProviderUnreachable)?
    .map_err(|_| Error::ProviderUnreachable)
}
async fn payload(
    socket: &mut Socket,
    transport: &Discord,
    resume: Option<&Resume>,
) -> ChannelResult<Value> {
    loop {
        match socket
            .next()
            .await
            .ok_or(Error::ProviderUnreachable)?
            .map_err(|_| Error::ProviderUnreachable)?
        {
            Message::Text(value) => {
                return serde_json::from_str(&value).map_err(|_| Error::ProviderProtocol);
            }
            Message::Ping(_) => tokio::time::timeout(Duration::from_secs(10), socket.flush())
                .await
                .map_err(|_| Error::ProviderUnreachable)?
                .map_err(|_| Error::ProviderUnreachable)?,
            Message::Pong(_) => {}
            Message::Close(frame) => {
                let code = frame.map(|f| u16::from(f.code));
                if matches!(code, Some(1000 | 1001 | 4007 | 4009)) {
                    if let Some(resume) = resume {
                        transport.invalidate(resume.session.clone())?;
                    }
                    return Err(Error::ReplayUnavailable);
                }
                return Err(match code {
                    Some(4004) => Error::InvalidToken,
                    Some(4010..=4014) => Error::Unsupported,
                    _ => Error::ProviderUnreachable,
                });
            }
            _ => return Err(Error::ProviderProtocol),
        }
    }
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
async fn run(
    transport: Arc<Discord>,
    token: &se_types::Secret,
    mut resume: Option<Resume>,
    rows: &mpsc::Sender<ChannelResult<Dispatch>>,
) -> ChannelResult<()> {
    if resume
        .as_ref()
        .map(|r| transport.invalid(&r.session))
        .transpose()?
        .unwrap_or(false)
    {
        resume = None;
    }
    let gateway = if let Some(resume) = &resume {
        resume.gateway.clone()
    } else {
        // One active receiver per bot; a new Identify follows the same token's
        // previous attempt by at least one concurrency window, the first
        // attempt waiting nothing. Spacing is per token, so simultaneous bots
        // do not pace each other. Reconnect with Resume skips it.
        transport.pace_identify(token).await?;
        let value = transport
            .request(token, Method::GET, "/gateway/bot", None)
            .await?;
        let limit = &value["session_start_limit"];
        if limit["remaining"].as_u64().ok_or(Error::ProviderProtocol)? == 0 {
            return Err(Error::RateLimited {
                retry_after_seconds: limit["reset_after"]
                    .as_u64()
                    .ok_or(Error::ProviderProtocol)?
                    .div_ceil(1000)
                    .clamp(1, 3600) as u32,
            });
        }
        value["url"]
            .as_str()
            .ok_or(Error::ProviderProtocol)?
            .to_owned()
    };
    let mut socket = socket(&transport, &gateway).await?;
    let hello = tokio::time::timeout(
        Duration::from_secs(10),
        payload(&mut socket, &transport, resume.as_ref()),
    )
    .await
    .map_err(|_| Error::ProviderUnreachable)??;
    if hello["op"].as_u64() == Some(7) {
        return Err(Error::ProviderUnreachable);
    }
    if hello["op"].as_u64() != Some(10) {
        return Err(Error::ProviderProtocol);
    }
    let interval = hello["d"]["heartbeat_interval"]
        .as_u64()
        .filter(|n| (100..=120_000).contains(n))
        .ok_or(Error::ProviderProtocol)?;
    let jitter = se_proc::random_secret().map_err(|_| Error::ReceiverNotRunning)?;
    let mut next_heartbeat =
        Instant::now() + Duration::from_millis(u64::from(jitter.expose()[0]) * interval / 256);
    let mut waiting_ack = false;
    let token_text = std::str::from_utf8(token.expose()).map_err(|_| Error::InvalidToken)?;
    let auth = match &resume {
        Some(r) => json!({"op":6,"d":{"token":token_text,"session_id":r.session,"seq":r.seq}}),
        None => {
            json!({"op":2,"d":{"token":token_text,"intents":4096,"properties":{"os":std::env::consts::OS,"browser":"StateEngine","device":"StateEngine"}}})
        }
    };
    send(&mut socket, auth).await?;
    let mut last_seen = resume.as_ref().map(|r| r.seq);
    loop {
        let value = tokio::select! {
            value=payload(&mut socket, &transport, resume.as_ref()) => value?,
            _=tokio::time::sleep_until(next_heartbeat) => {
                if waiting_ack { return Err(Error::ProviderUnreachable); }
                send(&mut socket, json!({"op":1,"d":last_seen})).await?;
                waiting_ack=true;
                next_heartbeat=Instant::now()+Duration::from_millis(interval);
                continue;
            }
        };
        match value["op"].as_u64() {
            Some(11) => waiting_ack = false,
            Some(1) => {
                send(&mut socket, json!({"op":1,"d":last_seen})).await?;
                waiting_ack = true;
            }
            Some(7) => return Err(Error::ProviderUnreachable),
            Some(9) => {
                if value["d"].as_bool() == Some(false) {
                    if let Some(resume) = &resume {
                        transport.invalidate(resume.session.clone())?;
                    }
                    return Err(Error::ReplayUnavailable);
                }
                return Err(Error::ProviderUnreachable);
            }
            Some(0) => {
                let seq = value["s"]
                    .as_u64()
                    .filter(|s| *s <= i64::MAX as u64 && last_seen.is_none_or(|last| *s > last))
                    .ok_or(Error::ProviderProtocol)?;
                last_seen = Some(seq);
                let kind = value["t"].as_str().ok_or(Error::ProviderProtocol)?;
                let data = &value["d"];
                if kind == "READY" {
                    resume = Some(Resume {
                        session: data["session_id"]
                            .as_str()
                            .ok_or(Error::ProviderProtocol)?
                            .into(),
                        gateway: data["resume_gateway_url"]
                            .as_str()
                            .ok_or(Error::ProviderProtocol)?
                            .into(),
                        seq,
                    });
                }
                let checkpoint = resume.as_mut().ok_or(Error::ProviderProtocol)?;
                checkpoint.seq = seq;
                let cursor = checkpoint.cursor()?;
                let (update, message) = if kind == "MESSAGE_CREATE" {
                    (id(&data["id"])?, Some(data.clone()))
                } else {
                    use sha2::{Digest, Sha256};
                    (
                        ExternalId::new(format!(
                            "gateway-{}-{seq}",
                            se_types::hex_lower(
                                &Sha256::digest(checkpoint.session.as_bytes())[..16]
                            )
                        ))
                        .map_err(|_| Error::ProviderProtocol)?,
                        None,
                    )
                };
                // Full queue means reconnect from the last durable checkpoint;
                // never consume the stream while silently discarding messages.
                rows.try_send(Ok(Dispatch {
                    update,
                    cursor,
                    message,
                }))
                .map_err(|_| Error::ProviderUnreachable)?;
            }
            _ => return Err(Error::ProviderProtocol),
        }
    }
}
