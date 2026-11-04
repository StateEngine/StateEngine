//! Canonical completed Codex items, from one retained app-server connection or
//! its pinned native rollout. Response items and deltas never become chat.
use se_types::{Body, ProviderSessionId, Result, SeError, SessionId};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

pub struct Completed {
    pub vendor: String,
    pub role: se_store::Role,
    pub text: Body,
}
fn invalid(expected: &str) -> SeError {
    SeError::invalid("Codex completed capture", expected)
}
fn id<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
        .ok_or_else(|| invalid("a bounded actual thread, turn or item ID"))
}
fn item(item: &Value, turn: &str, native: bool) -> Result<Option<Completed>> {
    let item_id = id(item, "id")?;
    let kind = item
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("an explicit completed item type"))?;
    if native
        && kind == "Extension"
        && !matches!(
            item.get("kind").and_then(Value::as_str),
            Some("clock.sleep" | "image_gen.generation" | "web.search")
        )
    {
        return Err(invalid("a supported native extension kind"));
    }
    let role = match (kind, native) {
        ("UserMessage", true) | ("userMessage", false) => se_store::Role::User,
        ("AgentMessage", true) | ("agentMessage", false) => se_store::Role::Assistant,
        (
            "FunctionCallOutput"
            | "HookPrompt"
            | "SubAgentActivity"
            | "Extension"
            | "Reasoning"
            | "CommandExecution"
            | "FileChange"
            | "McpToolCall"
            | "DynamicToolCall"
            | "CollabAgentToolCall"
            | "WebSearch"
            | "ImageView"
            | "ImageGeneration"
            | "EnteredReviewMode"
            | "ExitedReviewMode"
            | "ContextCompaction"
            | "Plan",
            true,
        )
        | (
            "functionCallOutput"
            | "hookPrompt"
            | "subAgentActivity"
            | "sleep"
            | "reasoning"
            | "commandExecution"
            | "fileChange"
            | "mcpToolCall"
            | "dynamicToolCall"
            | "collabAgentToolCall"
            | "webSearch"
            | "imageView"
            | "imageGeneration"
            | "enteredReviewMode"
            | "exitedReviewMode"
            | "contextCompaction"
            | "plan",
            false,
        ) => return Ok(None),
        _ => {
            return Err(invalid(
                "a supported completed item; preserve the cursor on schema drift",
            ));
        }
    };
    let text = if !native && role == se_store::Role::Assistant {
        item.get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("the completed assistant text"))?
            .to_owned()
    } else {
        let parts = item
            .get("content")
            .and_then(Value::as_array)
            .filter(|parts| parts.len() <= 256)
            .ok_or_else(|| invalid("bounded completed message blocks"))?;
        let mut text = String::new();
        for part in parts {
            let kind = part.get("type").and_then(Value::as_str);
            match kind {
                Some("text" | "Text") => {
                    let value = part
                        .get("text")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid("a text block string"))?;
                    let separator = role == se_store::Role::User && !text.is_empty();
                    if text
                        .len()
                        .saturating_add(value.len())
                        .saturating_add(usize::from(separator))
                        > Body::MAX_BYTES
                    {
                        return Err(invalid("completed text within the body limit"));
                    }
                    if separator {
                        text.push('\n');
                    }
                    text.push_str(value);
                }
                // Non-text inputs remain in native evidence. Never reinterpret
                // image bytes or references as user conversation prose.
                Some("image" | "localImage" | "skill" | "mention")
                    if role == se_store::Role::User => {}
                _ => return Err(invalid("supported completed message content")),
            }
        }
        text
    };
    if text.is_empty() {
        return Ok(None);
    }
    let vendor = serde_json::to_string(&[turn, item_id])
        .map_err(|_| invalid("an encodable completed-item identity"))?;
    Ok(Some(Completed {
        vendor,
        role,
        text: Body::new(text)?,
    }))
}
/// Only canonical item/completed notifications are accepted. A terminal turn
/// has no chat body but must still carry its actual thread, turn and status.
pub fn notification(value: &Value, conversation: &ProviderSessionId) -> Result<Option<Completed>> {
    let params = value
        .get("params")
        .ok_or_else(|| invalid("notification params"))?;
    if id(params, "threadId")? != conversation.as_str() {
        return Err(invalid("the exact initialized provider thread"));
    }
    match value.get("method").and_then(Value::as_str) {
        Some("item/completed") => item(
            params
                .get("item")
                .ok_or_else(|| invalid("a completed item"))?,
            id(params, "turnId")?,
            false,
        ),
        Some("turn/completed") => {
            let turn = params
                .get("turn")
                .ok_or_else(|| invalid("the terminal turn"))?;
            id(turn, "id")?;
            if !matches!(
                turn.get("status").and_then(Value::as_str),
                Some("completed" | "interrupted" | "failed")
            ) {
                return Err(invalid("a terminal provider turn status"));
            }
            Ok(None)
        }
        _ => Err(invalid("a canonical completed item or turn notification")),
    }
}
/// Native rollout item_completed is the persisted canonical item, with native
/// enum tags. Raw response_item messages are duplicate model traffic.
pub fn decode(bytes: &[u8], conversation: &ProviderSessionId) -> Result<Option<Completed>> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("a complete JSON rollout record"))?;
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("an explicit rollout record type"))?;
    let payload = value
        .get("payload")
        .ok_or_else(|| invalid("a rollout payload"))?;
    match kind {
        "session_meta" => {
            if id(payload, "id")? != conversation.as_str() {
                return Err(invalid("the bound native rollout session"));
            }
            Ok(None)
        }
        "event_msg" => {
            if let Some(thread) = payload.get("thread_id")
                && thread.as_str() != Some(conversation.as_str())
            {
                return Err(invalid("the bound thread on native events"));
            }
            match payload.get("type").and_then(Value::as_str) {
                Some("item_completed") => {
                    if id(payload, "thread_id")? != conversation.as_str() {
                        return Err(invalid("the bound thread on a completed item"));
                    }
                    item(
                        payload
                            .get("item")
                            .ok_or_else(|| invalid("a persisted completed item"))?,
                        id(payload, "turn_id")?,
                        true,
                    )
                }
                Some(_) => Ok(None),
                None => Err(invalid("a native event type")),
            }
        }
        "response_item" | "turn_context" | "world_state" | "compacted" | "token_usage_record" => {
            Ok(None)
        }
        _ => Err(invalid(
            "a supported rollout record; preserve the cursor on schema drift",
        )),
    }
}
pub fn turn_id(session: &SessionId, vendor: &str) -> Result<se_store::RecordId> {
    se_core::ops::process_commit::session_credential_id(session, &format!("codex-item:{vendor}"))
}
/// No arbitrary provider pathname grants read authority. NativeSourcePin then
/// checks every parent, ownership, no-follow and the exact file incarnation.
pub fn location(path: &Path, home: &Path) -> Result<PathBuf> {
    if !home.is_absolute()
        || !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "an absolute normalized rollout under the existing CODEX_HOME",
        ));
    }
    let relative = path
        .strip_prefix(home)
        .map_err(|_| invalid("a rollout inside the existing CODEX_HOME"))?;
    let mut parts = relative.components();
    if !matches!(parts.next(), Some(Component::Normal(name)) if name == "sessions" || name == "archived_sessions")
        || relative
            .file_name()
            .is_none_or(|name| !name.to_string_lossy().ends_with(".jsonl"))
    {
        return Err(invalid("a JSONL rollout in sessions or archived_sessions"));
    }
    Ok(path.into())
}
pub fn existing_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("CODEX_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .ok_or_else(|| invalid("the normal user home or explicit CODEX_HOME"))?;
    Ok(PathBuf::from(home).join(".codex"))
}

pub fn validate_header(
    pin: &mut se_proc::NativeSourcePin,
    conversation: &ProviderSessionId,
) -> Result<()> {
    let mut bytes = Vec::new();
    let mut position = 0;
    loop {
        let chunk = pin
            .read_at(position, 256 * 1024)
            .map_err(|_| invalid("a readable pinned rollout header"))?;
        if let Some(end) = chunk.bytes.iter().position(|byte| *byte == b'\n') {
            bytes.extend_from_slice(&chunk.bytes[..end]);
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("a complete native session header"))?;
            if value.get("type").and_then(Value::as_str) != Some("session_meta")
                || id(
                    value
                        .get("payload")
                        .ok_or_else(|| invalid("native session metadata"))?,
                    "id",
                )? != conversation.as_str()
            {
                return Err(invalid(
                    "the exact provider thread in the pinned rollout header",
                ));
            }
            return Ok(());
        }
        bytes.extend_from_slice(&chunk.bytes);
        if bytes.len() >= 4 * 1024 * 1024 || chunk.end_of_file {
            return Err(invalid("a complete native session header within 4 MiB"));
        }
        position = chunk.next_offset;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn persisted_and_live_items_have_one_identity_and_body()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let thread: ProviderSessionId = "provider-thread".parse()?;
        let live = json!({"method":"item/completed","params":{"threadId":"provider-thread","turnId":"t","item":{"id":"i","type":"agentMessage","text":"actual reply"}}});
        let native = json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"provider-thread","turn_id":"t","item":{"id":"i","type":"AgentMessage","content":[{"type":"Text","text":"actual reply"}]}}});
        let a = notification(&live, &thread)?.ok_or("live reply absent")?;
        let b = decode(&serde_json::to_vec(&native)?, &thread)?.ok_or("native reply absent")?;
        assert_eq!(a.vendor, b.vendor);
        assert_eq!(a.role, b.role);
        assert_eq!(a.text.as_str(), b.text.as_str());
        assert!(notification(&live, &"foreign-thread".parse()?).is_err());
        assert!(decode(&serde_json::to_vec(&native)?, &"foreign-thread".parse()?).is_err());
        let raw = json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"duplicate"}]}});
        assert!(decode(&serde_json::to_vec(&raw)?, &thread)?.is_none());
        for (native_type, live_type) in [
            ("FunctionCallOutput", "functionCallOutput"),
            ("HookPrompt", "hookPrompt"),
            ("SubAgentActivity", "subAgentActivity"),
            ("Extension", "sleep"),
        ] {
            let persisted = json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"provider-thread","turn_id":"t","item":{"id":"tool","type":native_type,"kind":"clock.sleep","durationMs":1000}}});
            let live = json!({"method":"item/completed","params":{"threadId":"provider-thread","turnId":"t","item":{"id":"tool","type":live_type,"durationMs":1000}}});
            assert!(decode(&serde_json::to_vec(&persisted)?, &thread)?.is_none());
            assert!(notification(&live, &thread)?.is_none());
        }
        Ok(())
    }
    #[test]
    fn provider_metadata_cannot_authorize_an_unrelated_path() {
        let home = if cfg!(windows) {
            PathBuf::from(r"C:\Users\capture\.codex")
        } else {
            PathBuf::from("/home/capture/.codex")
        };
        assert!(location(&home.join("sessions/2026/rollout.jsonl"), &home).is_ok());
        assert!(location(&home.join("sessions/../auth.json"), &home).is_err());
        assert!(location(&home.join("auth.json"), &home).is_err());
        assert!(
            location(
                &home
                    .with_extension("foreign")
                    .join("sessions/rollout.jsonl"),
                &home
            )
            .is_err()
        );
    }
}
