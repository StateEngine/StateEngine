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
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("an explicit string record type"))?;
    if kind != "user" && kind != "assistant" {
        if object.contains_key("sessionId")
            && object.get("sessionId").and_then(Value::as_str) != Some(conversation.as_str())
        {
            return Err(invalid(
                "the bound conversation when metadata names a session",
            ));
        }
        if noise_kind(kind)
            && !matches!(kind, "api-request-blob" | "queue-operation")
            && (object.contains_key("message") || object.contains_key("content"))
        {
            return Err(invalid("bookkeeping without message or content fields"));
        }
        if !known_metadata(kind)
            && matches!(
                object
                    .get("message")
                    .and_then(|m| m.get("role"))
                    .and_then(Value::as_str),
                Some("user" | "assistant")
            )
        {
            return Err(invalid(
                "a recognized text record type; an unknown message-bearing record may be a real turn",
            ));
        }
        let mut notice = se_core::ops::transcript::Record::new(
            kind,
            object.get("subtype").and_then(Value::as_str),
        );
        if kind == "queue-operation"
            && object.get("operation").and_then(Value::as_str) == Some("enqueue")
        {
            let text = object
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("the actual queued input text"))?;
            Body::new(text)?;
            notice.subtype = Some("enqueue".into());
            notice.queued_input = Some(se_core::ops::queued_input::QueuedInput {
                enqueue: Some(notice.position.clone()),
                outcome: se_core::ops::queued_input::Outcome::Unresolved,
                reason: None,
                delivery: se_core::ops::queued_input::Delivery::Unresolved,
                outcome_position: None,
                text: Some(text.into()),
            });
        }
        return Ok(Some(TextRecord {
            vendor_turn: String::new(),
            role: se_store::Role::System,
            text: notice.body()?,
        }));
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
                        tool_result(block.get("content"))?;
                    }
                    // These known blocks carry no visible chat prose. They remain
                    // in the source evidence digest; no text prefix is truncated.
                    Some("thinking" | "tool_use" | "fallback") if kind == "assistant" => (),
                    Some("image") if kind == "user" => (),
                    _ => return Err(unknown_block("content", block)),
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
fn tool_result(content: Option<&Value>) -> Result<()> {
    match content {
        Some(Value::String(_)) => Ok(()),
        Some(Value::Array(parts)) => {
            for part in parts {
                match part.get("type").and_then(Value::as_str) {
                    Some("text") if part.get("text").and_then(Value::as_str).is_some() => (),
                    // Tool search returns references to discovered tools. These
                    // remain source evidence, just like tool text; neither is
                    // a human message or public conversation prose.
                    Some("tool_reference")
                        if part
                            .get("tool_name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| {
                                !name.is_empty()
                                    && name.len() <= 512
                                    && !name.chars().any(char::is_control)
                            }) => {}
                    Some("text" | "tool_reference") => {
                        return Err(invalid(
                            "a tool-result text string or bounded tool reference name",
                        ));
                    }
                    _ => return Err(unknown_block("tool-result", part)),
                }
            }
            Ok(())
        }
        _ => Err(invalid("supported tool-result content")),
    }
}
fn unknown_block(context: &str, block: &Value) -> SeError {
    let Some(kind) = block.get("type").and_then(Value::as_str) else {
        return invalid("an explicit content block type");
    };
    let name: String = kind.chars().take(128).collect();
    let truncated = if name.len() < kind.len() {
        " (truncated)"
    } else {
        ""
    };
    SeError::invalid(
        &format!("pinned Claude transcript {context} block type {name:?}{truncated}"),
        "a supported content block; preserve the old cursor on schema drift",
    )
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

/// Frequent provider bookkeeping, summarized with the next captured record.
pub fn noise_kind(kind: &str) -> bool {
    matches!(
        kind,
        "file-history-snapshot"
            | "api-request-blob"
            | "api-request"
            | "api-request-shape"
            | "session-owner"
            | "tools-used"
            | "attachment"
            | "queue-operation"
            | "atis-latch"
            | "last-prompt"
            | "cost-state"
    )
}
fn known_metadata(kind: &str) -> bool {
    noise_kind(kind)
        || matches!(
            kind,
            "system" | "compact_boundary" | "mode" | "permission-mode" | "ai-title"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metadata_cannot_override_the_bound_session_or_hide_content()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = ProviderSessionId::new("bound-session")?;
        for value in [
            json!({"type":"file-history-snapshot","message":null}),
            json!({"type":"mode","sessionId":"foreign-session"}),
            json!({"type":"mode","sessionId":null}),
        ] {
            assert!(decode(&serde_json::to_vec(&value)?, &session).is_err());
        }
        for value in [
            json!({"type":"file-history-snapshot","snapshot":{}}),
            json!({"type":"api-request-blob","content":"native model traffic"}),
            json!({"type":"queue-operation","operation":"remove","content":"provider bookkeeping"}),
            json!({"type":"mode","sessionId":"bound-session"}),
        ] {
            assert!(decode(&serde_json::to_vec(&value)?, &session)?.is_some());
        }
        Ok(())
    }
}
