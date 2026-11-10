//! Copy display observations only after the owned binding matches thread/turn.
//! The canonical capture queue is neither read, acknowledged nor modified here.
use super::*;
use crate::remote::RemoteTurnRole;
impl Binding {
    pub(super) fn observe_live(&self, method: &str, params: &Value) {
        let source = match self.live.lock() {
            Ok(live) => live.clone(),
            Err(_) => return,
        };
        let Some(source) = source else {
            return;
        };
        if !matches!(method, "item/agentMessage/delta" | "item/completed") {
            return;
        }
        let (conversation, turn) = match self.state.lock() {
            Ok(state) if !state.restoring => {
                let Some(conversation) = state.conversation.as_ref() else {
                    return;
                };
                let Some(turn) = params.get("turnId").and_then(Value::as_str) else {
                    return;
                };
                if params.get("threadId").and_then(Value::as_str) != Some(conversation.as_str())
                    || (state.active_turn.as_deref() != Some(turn)
                        && !state.completed.iter().any(|t| t == turn))
                {
                    return;
                }
                (conversation.clone(), turn.to_owned())
            }
            _ => return,
        };
        if method == "item/agentMessage/delta" {
            let Some(item) = params.get("itemId").and_then(Value::as_str).filter(|id| {
                !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control)
            }) else {
                return;
            };
            let Some(delta) = params.get("delta").and_then(Value::as_str) else {
                return;
            };
            if let Ok(vendor) = serde_json::to_string(&[turn.as_str(), item]) {
                source.delta(&vendor, RemoteTurnRole::Assistant, delta);
            }
        } else if params.get("threadId").and_then(Value::as_str) == Some(conversation.as_str())
            && let Some(item) = params.get("item")
            && let Ok(Some(record)) = crate::codex_capture::item(item, &turn, false)
        {
            let role = match record.role {
                se_store::Role::User => RemoteTurnRole::User,
                se_store::Role::Assistant => RemoteTurnRole::Assistant,
                se_store::Role::Tool => RemoteTurnRole::Tool,
                _ => return,
            };
            source.complete(&record.vendor, role, record.text.as_str());
        }
    }
}
