//! Private direct messages through the bot API. Tokens stay in sensitive headers;
//! provider error bodies, redirects and automatic HTTP retries never escape here.
use super::*;
use reqwest::{Method, header};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
mod gateway;
mod message;
#[cfg(all(test, target_os = "linux"))]
mod review;
use gateway::Receiver;

type Error = ChannelError;
const API: &str = "https://discord.com/api/v10";
/// One gateway concurrency window, in microseconds: a fresh Identify follows
/// the previous attempt by at least this long, the very first attempt
/// excepted. The window is the spacing the fixed pre-Identify sleep used.
const IDENTIFY_WINDOW_US: u64 = 5 * 1_000_000;
pub struct Discord {
    client: reqwest::Client,
    invalid_sessions: Mutex<VecDeque<String>>,
    /// Unix microseconds of the last fresh Identify attempt, 0 while there is
    /// none: the attempt consumed a concurrency window even if it failed.
    last_identify: AtomicU64,
}
impl Discord {
    fn client_builder() -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .user_agent("DiscordBot (https://github.com/StateEngine/StateEngine, 1)")
    }
    pub fn new() -> ChannelResult<Self> {
        let client = Self::client_builder()
            .build()
            .map_err(|_| Error::ProviderUnreachable)?;
        Ok(Self {
            client,
            invalid_sessions: Mutex::default(),
            last_identify: AtomicU64::new(0),
        })
    }
    /// Paces a fresh Identify attempt against the previous one, which consumed
    /// a gateway concurrency window even if it ended in a refusal; the first
    /// attempt waits nothing.
    async fn pace_identify(&self) {
        if let Some(wait) = identify_wait(self.last_identify.load(Ordering::Relaxed), unix_micros())
        {
            tokio::time::sleep(wait).await;
        }
    }
    fn note_identify(&self) {
        self.last_identify.store(unix_micros(), Ordering::Relaxed);
    }
    fn authorization(token: &se_types::Secret) -> ChannelResult<header::HeaderValue> {
        let bytes = token.expose();
        if bytes.is_empty() || bytes.len() > 256 || !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(Error::InvalidToken);
        }
        let token = std::str::from_utf8(bytes).map_err(|_| Error::InvalidToken)?;
        let text = zeroize::Zeroizing::new(format!("Bot {token}"));
        let mut value = header::HeaderValue::from_str(&text).map_err(|_| Error::InvalidToken)?;
        value.set_sensitive(true);
        Ok(value)
    }
    async fn request(
        &self,
        token: &se_types::Secret,
        method: Method,
        route: &str,
        body: Option<Value>,
    ) -> ChannelResult<Value> {
        let sending = method == Method::POST;
        let unknown = || {
            if sending {
                Error::SendOutcomeUnknown
            } else {
                Error::ProviderUnreachable
            }
        };
        let mut request = self
            .client
            .request(method, format!("{API}{route}"))
            .header(header::AUTHORIZATION, Self::authorization(token)?)
            .timeout(Duration::from_secs(10));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request.send().await.map_err(|_| unknown())?;
        let status = response.status();
        if response.content_length().is_some_and(|n| n > 256 * 1024) {
            return Err(unknown());
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| unknown())? {
            if bytes.len() + chunk.len() > 256 * 1024 {
                return Err(unknown());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| unknown())?;
        if status.is_success() {
            return Ok(value);
        }
        Err(match status.as_u16() {
            401 => Error::InvalidToken,
            400 | 403 | 404 => Error::Unsupported,
            429 => Error::RateLimited {
                retry_after_seconds: value["retry_after"]
                    .as_f64()
                    .filter(|n| n.is_finite() && *n > 0.0)
                    .unwrap_or(60.0)
                    .ceil()
                    .clamp(1.0, 3600.0) as u32,
            },
            _ => unknown(),
        })
    }
    fn invalid(&self, session: &str) -> ChannelResult<bool> {
        Ok(self
            .invalid_sessions
            .lock()
            .map_err(|_| Error::ReceiverNotRunning)?
            .iter()
            .any(|s| s == session))
    }
    fn invalidate(&self, session: String) -> ChannelResult<()> {
        let mut sessions = self
            .invalid_sessions
            .lock()
            .map_err(|_| Error::ReceiverNotRunning)?;
        if !sessions.contains(&session) {
            if sessions.len() == se_store::channel::MAX_CONNECTIONS {
                sessions.pop_front();
            }
            sessions.push_back(session);
        }
        Ok(())
    }
}
/// Unix microseconds since the epoch, saturating at both ends: a pre-epoch
/// clock reads as the epoch, which can only make a later attempt wait the
/// full window.
fn unix_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
/// The wait a fresh Identify attempt owes its predecessor: the first waits
/// nothing, a later attempt waits out the remaining concurrency window, capped
/// at one full window so a backwards clock can never wait longer.
fn identify_wait(last_unix_us: u64, now_unix_us: u64) -> Option<Duration> {
    if last_unix_us == 0 {
        return None;
    }
    let wait = last_unix_us
        .saturating_add(IDENTIFY_WINDOW_US)
        .saturating_sub(now_unix_us);
    (wait > 0).then(|| Duration::from_micros(wait.min(IDENTIFY_WINDOW_US)))
}
fn id(value: &Value) -> ChannelResult<ExternalId> {
    let text = value.as_str().ok_or(Error::ProviderProtocol)?;
    if text.len() > 20
        || !text.bytes().all(|b| b.is_ascii_digit())
        || text.starts_with('0')
        || text.parse::<u64>().ok().is_none_or(|id| id == 0)
    {
        return Err(Error::ProviderProtocol);
    }
    ExternalId::new(text.into()).map_err(|_| Error::ProviderProtocol)
}
impl ChannelTransport for Discord {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: Connector::Discord,
            name: "Discord",
            max_text_utf16: 2000,
            edits: false,
            buttons: false,
            threads: false,
            media: false,
            identity_proof: "authenticated_human_sender_in_verified_one_to_one_direct_channel",
            acknowledgement: "saved_gateway_checkpoint_after_durable_disposition",
            reconnect: "gateway_resume_or_visible_receive_gap",
            retention_seconds: None,
            setup: &[SetupField {
                key: "token",
                label: "Bot token",
                secret: true,
                required: true,
            }],
            instructions: "Create a bot application, install it in a server you own, and enter its token in the protected field. Open its profile, send the shown pairing message in a direct message, then approve the exact sender in StateEngine. Only direct text is supported; no privileged message-content intent is needed for direct messages.",
        }
    }
    fn identity<'a>(&'a self, token: &'a se_types::Secret) -> TransportFuture<'a, BotIdentity> {
        Box::pin(async move {
            let user = self.request(token, Method::GET, "/users/@me", None).await?;
            if user["bot"].as_bool() != Some(true) {
                return Err(Error::InvalidToken);
            }
            let username = user["username"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .ok_or(Error::ProviderProtocol)?;
            let display = user["global_name"].as_str().unwrap_or(username);
            if display.len() > 256 {
                return Err(Error::ProviderProtocol);
            }
            Ok(BotIdentity {
                id: id(&user["id"])?,
                username: username.into(),
                display_name: display.into(),
            })
        })
    }
    fn receiver(
        self: std::sync::Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>> {
        Ok(Box::new(Receiver::new(self, cursor)?))
    }
    fn pairing_link(&self, bot: &BotIdentity, _: &str) -> ChannelResult<se_types::Secret> {
        id(&Value::String(bot.id.to_string()))?;
        se_types::Secret::new(format!("https://discord.com/users/{}", bot.id).into_bytes())
            .map_err(|_| Error::InvalidInput)
    }
    fn answer_callback<'a>(
        &'a self,
        _: &'a se_types::Secret,
        _: &'a str,
        _: bool,
    ) -> TransportFuture<'a, ()> {
        Box::pin(async { Err(Error::Unsupported) })
    }
    fn send<'a>(
        &'a self,
        token: &'a se_types::Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId> {
        Box::pin(async move {
            id(&Value::String(chat.to_string()))?;
            if !buttons.is_empty() || text.is_empty() || text.encode_utf16().count() > 2000 {
                return Err(Error::MessageTooLarge);
            }
            let value = self
                .request(
                    token,
                    Method::POST,
                    &format!("/channels/{chat}/messages"),
                    Some(json!({"content":text,"allowed_mentions":{"parse":[]}})),
                )
                .await?;
            id(&value["id"]).map_err(|_| Error::SendOutcomeUnknown)
        })
    }
}
