//! Gateway delivery is not identity proof: verify the private channel with the
//! authenticated bot API before allowing a human sender into shared pairing.
use super::*;
use std::collections::HashSet;

pub(super) async fn normalize(
    transport: &Discord,
    token: &se_types::Secret,
    value: &Value,
    direct: &mut HashSet<(ExternalId, ExternalId)>,
) -> ChannelResult<IncomingContent> {
    if value.get("guild_id").is_some_and(|v| !v.is_null())
        || value.get("webhook_id").is_some()
        || value["author"]["bot"].as_bool().unwrap_or(false)
    {
        return Ok(IncomingContent::Unsupported);
    }
    let subject = id(&value["author"]["id"])?;
    let chat = id(&value["channel_id"])?;
    let key = (subject.clone(), chat.clone());
    if !direct.contains(&key) {
        let channel = transport
            .request(token, Method::GET, &format!("/channels/{chat}"), None)
            .await?;
        if channel["type"].as_u64() != Some(1) {
            return Ok(IncomingContent::Unsupported);
        }
        let recipients = channel["recipients"]
            .as_array()
            .ok_or(Error::ProviderProtocol)?;
        if recipients.len() != 1 || id(&recipients[0]["id"])? != subject {
            return Ok(IncomingContent::Unsupported);
        }
        if direct.len() < se_store::channel::MAX_CONNECTIONS {
            direct.insert(key);
        }
    }
    let author = &value["author"];
    let username = author["username"].as_str().ok_or(Error::ProviderProtocol)?;
    let display = author["global_name"].as_str().unwrap_or(username);
    if username.len() > 256 || display.len() > 256 {
        return Err(Error::ProviderProtocol);
    }
    let phone = PhoneIdentity {
        subject,
        private_chat: chat,
        display_name: display.into(),
        username: Some(username.into()),
    };
    let unsupported = [
        "attachments",
        "embeds",
        "components",
        "sticker_items",
        "message_snapshots",
    ]
    .iter()
    .any(|field| {
        value[*field]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    }) || value.get("poll").is_some_and(|v| !v.is_null())
        || !matches!(value["type"].as_u64(), Some(0 | 19));
    if unsupported {
        return Ok(IncomingContent::UnsupportedPrivate { phone });
    }
    Ok(match value["content"].as_str() {
        Some(text) if !text.is_empty() => IncomingContent::Text {
            phone,
            text: text.into(),
        },
        _ => IncomingContent::UnsupportedPrivate { phone },
    })
}
