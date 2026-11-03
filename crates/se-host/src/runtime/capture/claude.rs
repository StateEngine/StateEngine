//! Text records from the pinned Claude JSONL source. The stable record uuid is
//! the item identity; requestId can span several records and is not a turn key.
use se_types::{Body, ProviderSessionId, Result, SeError};
use serde_json::Value;
pub struct TextRecord {
    pub vendor_turn: String,
    pub role: se_store::Role,
    pub text: Body,
}
pub fn decode(bytes: &[u8], conversation: &ProviderSessionId) -> Result<Option<TextRecord>> {
    if bytes
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Ok(None);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("a complete JSON record"))?;
    let object = value.as_object().ok_or_else(|| invalid("a JSON object"))?;
    if let Some(session) = object.get("sessionId")
        && session.as_str() != Some(conversation.as_str())
    {
        return Err(invalid(
            "the bound provider conversation on every session-bearing record",
        ));
    }
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("a recognized record type"))?;
    if kind != "user" && kind != "assistant" {
        // Claude's request cache repeats API messages, including system text;
        // these are not conversation records and have no vendor turn uuid.
        // Recognize its explicit envelope without accepting arbitrary records
        // carrying message text as metadata.
        if kind == "api-request-blob"
            && !object.contains_key("uuid")
            && !object.contains_key("content")
            && object
                .get("hash")
                .and_then(Value::as_str)
                .is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            && object
                .get("message")
                .and_then(Value::as_object)
                .is_some_and(|message| {
                    matches!(
                        message.get("role").and_then(Value::as_str),
                        Some("system" | "user" | "assistant")
                    ) && matches!(
                        message.get("content"),
                        Some(Value::String(_) | Value::Array(_))
                    )
                })
        {
            return Ok(None);
        }
        // Known non-turn metadata contains no message/body. Unknown kinds stop
        // the cursor so a future schema change cannot silently discard text.
        if matches!(
            kind,
            "mode"
                | "file-history-snapshot"
                | "file-history-delta"
                | "system"
                | "attachment"
                | "ai-title"
                | "last-prompt"
                | "permission-mode"
                | "queue-operation"
                | "agent-name"
                | "frame-link"
                | "custom-title"
                | "bridge-session"
                | "atis-latch"
                | "cost-state"
                | "artifact-comment-monitor"
                | "artifact-autoreact-ledger"
                | "relocated"
                | "worktree-state"
                | "session-owner"
                | "tools-used"
                | "api-request-shape"
                | "api-request"
        ) && !object.contains_key("message")
            && !object.contains_key("content")
        {
            return Ok(None);
        }
        return Err(SeError::invalid(
            &format!("pinned Claude transcript record type {kind:?}"),
            "a supported transcript record; preserve the old cursor on schema drift",
        ));
    }
    if object.get("sessionId").and_then(Value::as_str) != Some(conversation.as_str()) {
        return Err(invalid("the actual bound conversation on a text record"));
    }
    if object.get("isSidechain").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    let vendor_turn = object
        .get("uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("a stable vendor record uuid"))?;
    if vendor_turn.is_empty() || vendor_turn.len() > 512 || vendor_turn.contains('\0') {
        return Err(invalid("a bounded nonempty vendor record uuid"));
    }
    let message = object
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("a provider message object"))?;
    if message.get("role").and_then(Value::as_str) != Some(kind) {
        return Err(invalid("matching record and message roles"));
    }
    if kind == "assistant" && message.get("model").and_then(Value::as_str) == Some("<synthetic>") {
        return Ok(None);
    }
    let content = message
        .get("content")
        .ok_or_else(|| invalid("a provider content field"))?;
    let mut text = String::new();
    match content {
        Value::String(value) => append(&mut text, value)?,
        Value::Array(blocks) => {
            for block in blocks {
                match block.get("type").and_then(Value::as_str) {
                    Some("text") => append(
                        &mut text,
                        block
                            .get("text")
                            .and_then(Value::as_str)
                            .ok_or_else(|| invalid("a text block string"))?,
                    )?,
                    Some("tool_result") if kind == "user" => {
                        // Tool replies stay in the pinned source evidence;
                        // the public chat family contains user/assistant turns.
                        match block.get("content") {
                            Some(Value::String(_)) => (),
                            Some(Value::Array(parts)) => {
                                for part in parts {
                                    if part.get("type").and_then(Value::as_str) != Some("text")
                                        || part.get("text").and_then(Value::as_str).is_none()
                                    {
                                        return Err(invalid("supported tool-result text blocks"));
                                    }
                                }
                            }
                            _ => return Err(invalid("supported tool-result content")),
                        }
                    }
                    // These known blocks carry no visible chat prose. They remain
                    // in the source evidence digest; no text prefix is truncated.
                    Some("thinking" | "tool_use" | "fallback") if kind == "assistant" => (),
                    Some("image") if kind == "user" => (),
                    _ => {
                        return Err(invalid(
                            "supported content blocks; unknown blocks retain the cursor",
                        ));
                    }
                }
            }
        }
        _ => return Err(invalid("string or block-array content")),
    }
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(TextRecord {
        vendor_turn: vendor_turn.into(),
        role: if kind == "user" {
            se_store::Role::User
        } else {
            se_store::Role::Assistant
        },
        text: Body::new(text)?,
    }))
}
fn append(target: &mut String, value: &str) -> Result<()> {
    let length = target
        .len()
        .checked_add(value.len())
        .ok_or_else(|| invalid("a bounded body"))?;
    if length > Body::MAX_BYTES {
        return Err(SeError::too_large("capture body", Body::MAX_BYTES, length));
    }
    if value.contains('\0') {
        return Err(invalid("text without NUL"));
    }
    target.push_str(value);
    Ok(())
}
fn invalid(expected: &str) -> SeError {
    SeError::invalid("pinned Claude transcript", expected)
}
