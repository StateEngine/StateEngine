//! Private-text Telegram transport. Error bodies and token-bearing URLs never
//! escape this module. Redirects, proxies and automatic retries are disabled.
use super::{BotIdentity, ChannelError as Error, ChannelResult, PhoneIdentity};
use se_types::Secret;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

pub struct Telegram {
    client: reqwest::Client,
}
#[derive(Clone)]
pub struct Incoming {
    pub update: i64,
    pub content: IncomingContent,
}
#[derive(Clone)]
pub enum IncomingContent {
    Text {
        phone: PhoneIdentity,
        text: String,
    },
    Callback {
        phone: PhoneIdentity,
        data: String,
        callback_id: String,
    },
    UnsupportedPrivate {
        phone: PhoneIdentity,
    },
    Unsupported,
}
impl Telegram {
    pub fn new() -> ChannelResult<Self> {
        reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(35))
            .user_agent("StateEngine Channels")
            .build()
            .map(|client| Self { client })
            .map_err(|_| Error::ProviderUnreachable)
    }
    pub async fn identity(&self, token: &Secret) -> ChannelResult<BotIdentity> {
        let result = self.call(token, "getMe", json!({})).await?;
        if result.get("is_bot").and_then(Value::as_bool) != Some(true) {
            return Err(Error::InvalidToken);
        }
        let id = result
            .get("id")
            .and_then(Value::as_i64)
            .filter(|n| *n > 0)
            .ok_or(Error::ProviderProtocol)?;
        let username = result
            .get("username")
            .and_then(Value::as_str)
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .ok_or(Error::ProviderProtocol)?
            .to_owned();
        let display_name = name(&result)?;
        Ok(BotIdentity {
            id,
            username,
            display_name,
        })
    }
    pub async fn poll(&self, token: &Secret, offset: Option<i64>) -> ChannelResult<Vec<Incoming>> {
        let mut args =
            json!({"timeout":25,"limit":10,"allowed_updates":["message","callback_query"]});
        if let Some(offset) = offset {
            if offset < 0 {
                return Err(Error::InvalidInput);
            }
            args["offset"] = json!(offset);
        }
        let value = self.call(token, "getUpdates", args).await?;
        let rows = value
            .as_array()
            .filter(|v| v.len() <= 10)
            .ok_or(Error::ProviderProtocol)?;
        let mut updates = Vec::new();
        for row in rows {
            let update = row
                .get("update_id")
                .and_then(Value::as_i64)
                .filter(|n| *n >= 0 && *n < i64::MAX)
                .ok_or(Error::ProviderProtocol)?;
            // Offset advancement relies on ordered handling of this exact batch.
            if updates
                .last()
                .is_some_and(|prior: &Incoming| prior.update >= update)
            {
                return Err(Error::ProviderProtocol);
            }
            updates.push(Incoming {
                update,
                content: normalize(row)?,
            });
        }
        Ok(updates)
    }
    pub async fn answer_callback(
        &self,
        token: &Secret,
        id: &str,
        accepted: bool,
    ) -> ChannelResult<()> {
        if id.is_empty() || id.len() > 256 {
            return Err(Error::InvalidInput);
        }
        let text = if accepted {
            "Confirmation saved. Check this chat for the lifecycle result."
        } else {
            "No action was applied. Check this chat for its status."
        };
        let result = self
            .call(
                token,
                "answerCallbackQuery",
                json!({"callback_query_id":id,"text":text,"show_alert":false,"cache_time":0}),
            )
            .await?;
        if result.as_bool() != Some(true) {
            return Err(Error::ProviderProtocol);
        }
        Ok(())
    }
    pub async fn send(
        &self,
        token: &Secret,
        chat: i64,
        text: &str,
        keyboard: Option<Value>,
    ) -> ChannelResult<i64> {
        if chat <= 0 || text.is_empty() || text.encode_utf16().count() > 4096 {
            return Err(Error::MessageTooLarge);
        }
        let mut args =
            json!({"chat_id":chat,"text":text,"link_preview_options":{"is_disabled":true}});
        if let Some(keyboard) = keyboard {
            args["reply_markup"] = keyboard;
        }
        let value = self.call(token, "sendMessage", args).await?;
        value
            .get("message_id")
            .and_then(Value::as_i64)
            .filter(|n| *n > 0)
            .ok_or(Error::SendOutcomeUnknown)
    }
    async fn call(
        &self,
        token: &Secret,
        method: &'static str,
        args: Value,
    ) -> ChannelResult<Value> {
        super::credentials::validate_token(token.expose())?;
        let token = std::str::from_utf8(token.expose()).map_err(|_| Error::InvalidToken)?;
        let url = zeroize::Zeroizing::new(format!("https://api.telegram.org/bot{token}/{method}"));
        let sending = method == "sendMessage";
        let unknown = || {
            if sending {
                Error::SendOutcomeUnknown
            } else {
                Error::ProviderUnreachable
            }
        };
        let mut response = self
            .client
            .post(url.as_str())
            .timeout(Duration::from_secs(if method == "getUpdates" {
                35
            } else {
                10
            }))
            .json(&args)
            .send()
            .await
            .map_err(|_| unknown())?;
        if response.content_length().is_some_and(|n| n > 256 * 1024) {
            return Err(if sending {
                Error::SendOutcomeUnknown
            } else {
                Error::ProviderProtocol
            });
        }
        let status = response.status().as_u16();
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| unknown())? {
            if bytes.len() + chunk.len() > 256 * 1024 {
                return Err(if sending {
                    Error::SendOutcomeUnknown
                } else {
                    Error::ProviderProtocol
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        struct Envelope {
            ok: bool,
            result: Option<Value>,
            error_code: Option<u16>,
            parameters: Option<Parameters>,
        }
        #[derive(Deserialize)]
        struct Parameters {
            retry_after: Option<u32>,
        }
        let reply: Envelope = serde_json::from_slice(&bytes).map_err(|_| {
            if sending {
                Error::SendOutcomeUnknown
            } else {
                Error::ProviderProtocol
            }
        })?;
        if reply.ok && (200..300).contains(&status) {
            return reply.result.ok_or_else(unknown);
        }
        Err(match reply.error_code.unwrap_or(status) {
            401 | 404 => Error::InvalidToken,
            409 => Error::PollerConflict,
            429 => Error::RateLimited {
                retry_after_seconds: reply
                    .parameters
                    .and_then(|p| p.retry_after)
                    .unwrap_or(60)
                    .clamp(1, 3600),
            },
            400 | 403 => Error::Unsupported,
            _ => unknown(),
        })
    }
}
fn name(value: &Value) -> ChannelResult<String> {
    let first = value
        .get("first_name")
        .and_then(Value::as_str)
        .ok_or(Error::ProviderProtocol)?;
    let last = value.get("last_name").and_then(Value::as_str).unwrap_or("");
    let name = if last.is_empty() {
        first.to_owned()
    } else {
        format!("{first} {last}")
    };
    if name.len() > 256 {
        return Err(Error::ProviderProtocol);
    }
    Ok(name)
}
fn phone(user: &Value, chat: &Value) -> ChannelResult<Option<PhoneIdentity>> {
    let Some(subject) = user.get("id").and_then(Value::as_i64).filter(|n| *n > 0) else {
        return Ok(None);
    };
    if user.get("is_bot").and_then(Value::as_bool) != Some(false)
        || chat.get("type").and_then(Value::as_str) != Some("private")
        || chat.get("id").and_then(Value::as_i64) != Some(subject)
    {
        return Ok(None);
    }
    let username = user
        .get("username")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if username
        .as_ref()
        .is_some_and(|s| s.len() > 64 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return Err(Error::ProviderProtocol);
    }
    Ok(Some(PhoneIdentity {
        subject,
        private_chat: subject,
        display_name: name(user)?,
        username,
    }))
}
fn normalize(value: &Value) -> ChannelResult<IncomingContent> {
    if let Some(callback) = value.get("callback_query") {
        let message = &callback["message"];
        if let Some(phone) = phone(&callback["from"], &message["chat"])?
            && let (Some(data), Some(id)) = (callback["data"].as_str(), callback["id"].as_str())
            && data.len() <= 64
            && id.len() <= 256
        {
            return Ok(IncomingContent::Callback {
                phone,
                data: data.to_owned(),
                callback_id: id.to_owned(),
            });
        }
        return Ok(IncomingContent::Unsupported);
    }
    let Some(message) = value.get("message") else {
        return Ok(IncomingContent::Unsupported);
    };
    let Some(phone) = phone(&message["from"], &message["chat"])? else {
        return Ok(IncomingContent::Unsupported);
    };
    // A caption is not a supported text message; attachments never disappear
    // silently into an instruction that claims their contents were saved.
    let attachments = [
        "photo",
        "video",
        "audio",
        "voice",
        "document",
        "sticker",
        "contact",
        "location",
        "poll",
        "animation",
        "paid_media",
        "rich_message",
    ];
    if message.get("sender_chat").is_some() {
        return Ok(IncomingContent::Unsupported);
    }
    if attachments.iter().any(|k| message.get(k).is_some()) {
        return Ok(IncomingContent::UnsupportedPrivate { phone });
    }
    match message.get("text").and_then(Value::as_str) {
        Some(text) => Ok(IncomingContent::Text {
            phone,
            text: text.to_owned(),
        }),
        None => Ok(IncomingContent::UnsupportedPrivate { phone }),
    }
}

#[cfg(test)]
#[path = "telegram_tests.rs"]
mod tests;
