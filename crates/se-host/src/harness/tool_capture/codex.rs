//! Canonical tool completions only; raw response items and deltas are duplicates.
use super::*;
use se_types::ProviderSessionId;
use serde_json::Value;

pub(crate) fn decode(bytes: &[u8], conversation: &ProviderSessionId) -> Result<Option<Fact>> {
    let value: Value = serde_json::from_slice(bytes).map_err(json_error)?;
    if value.get("type").and_then(Value::as_str) != Some("event_msg")
        || value.pointer("/payload/type").and_then(Value::as_str) != Some("item_completed")
    {
        return Ok(None);
    }
    let payload = &value["payload"];
    if payload.get("thread_id").and_then(Value::as_str) != Some(conversation.as_str()) {
        return Err(SeError::invalid(
            "native tool thread",
            "the bound Codex conversation",
        ));
    }
    item(&payload["item"], payload.get("turn_id"))
}
pub(crate) fn notification(
    value: &Value,
    conversation: &ProviderSessionId,
) -> Result<Option<Fact>> {
    if value.get("method").and_then(Value::as_str) != Some("item/completed") {
        return Ok(None);
    }
    let params = &value["params"];
    if params.get("threadId").and_then(Value::as_str) != Some(conversation.as_str()) {
        return Err(SeError::invalid(
            "native tool thread",
            "the bound Codex conversation",
        ));
    }
    item(&params["item"], params.get("turnId"))
}
fn item(value: &Value, turn: Option<&Value>) -> Result<Option<Fact>> {
    let kind = value.get("type").and_then(Value::as_str);
    if !matches!(
        kind,
        Some("FileChange" | "fileChange" | "McpToolCall" | "mcpToolCall")
    ) {
        return Ok(None);
    }
    let turn_id = label(turn, 256);
    let item_id = label(value.get("id"), 256);
    let call_id = label(value.get("call_id").or_else(|| value.get("callId")), 256);
    let native = if item_id.is_some() || call_id.is_some() {
        NativeIdentity::CodexItem {
            turn_id,
            item_id,
            call_id,
        }
    } else {
        NativeIdentity::Unknown(UnknownReason::NoNativeIdentity)
    };
    // Keep the namespaces in the durable key, even when a field is over budget.
    let key = serde_json::to_string(&(
        turn,
        value.get("id"),
        value.get("call_id").or_else(|| value.get("callId")),
    ))
    .map_err(json_error)?;
    let key = if matches!(native, NativeIdentity::Unknown(_)) {
        format!(
            "{key}/{}",
            se_types::hex_lower(&Sha256::digest(
                serde_json::to_vec(value).map_err(json_error)?
            ))
        )
    } else {
        key
    };
    let outcome = match value.get("status").and_then(Value::as_str) {
        Some("completed" | "Completed") if value.get("error").is_some_and(|e| !e.is_null()) => {
            Outcome::Unknown(UnknownReason::ConflictingEvidence)
        }
        Some("completed" | "Completed") => Outcome::Succeeded,
        Some("failed" | "Failed") => Outcome::Failed,
        Some("declined" | "Declined" | "cancelled" | "Cancelled") => Outcome::Cancelled,
        Some("inProgress" | "InProgress") => Outcome::Unknown(UnknownReason::Pending),
        _ => Outcome::Unknown(UnknownReason::NoNativeOutcome),
    };
    let (tool, target) = if matches!(kind, Some("FileChange" | "fileChange")) {
        (ToolName::Known("FileChange".into()), changed_paths(value))
    } else {
        (
            tool(value.get("tool")),
            super::targets::arguments(value.get("arguments"), value.get("cwd")),
        )
    };
    Ok(Some(Fact {
        key,
        native,
        phase: Phase::Completed,
        tool,
        target,
        outcome,
    }))
}
fn changed_paths(value: &Value) -> Target {
    let mut paths = Vec::new();
    match value.get("changes") {
        Some(Value::Array(changes)) => {
            if changes.len() > 16 {
                return Target::Unknown(UnknownReason::OverBudget);
            }
            for change in changes {
                let Some(path) = change.get("path") else {
                    return Target::Unknown(UnknownReason::UnsupportedShape);
                };
                paths.push(path.clone());
                if let Some(moved) = change.pointer("/kind/move_path").filter(|v| !v.is_null()) {
                    paths.push(moved.clone());
                }
            }
        }
        _ => return Target::Unknown(UnknownReason::UnsupportedShape),
    }
    super::targets::paths(paths.iter().collect(), value.get("cwd"))
}
