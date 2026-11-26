//! Context usage from the bound conversation's stream frames. Reading it never
//! fails the binding: a frame this does not understand simply reports nothing.
use crate::harness::context_usage::ContextUsage;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Context {
    usage: Option<ContextUsage>,
    /// The model behind the latest main-conversation reply, used to pick its
    /// window out of the turn result's per-model totals.
    model: Option<String>,
}
#[derive(Deserialize)]
struct Frame {
    #[serde(rename = "type")]
    kind: String,
    session_id: Option<String>,
    parent_tool_use_id: Option<String>,
    message: Option<Message>,
    #[serde(rename = "modelUsage")]
    model_usage: Option<BTreeMap<String, ModelUsage>>,
}
#[derive(Deserialize)]
struct Message {
    model: Option<String>,
    usage: Option<Usage>,
}
/// One request's input side: fresh input plus cache writes and cache reads is
/// everything the model read, which is what the conversation occupies now.
#[derive(Deserialize)]
struct Usage {
    input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}
#[derive(Deserialize)]
struct ModelUsage {
    #[serde(rename = "contextWindow")]
    context_window: Option<u64>,
}
impl Context {
    pub(super) fn latest(&self) -> Option<ContextUsage> {
        self.usage
    }
    pub(super) fn observe(&mut self, line: &[u8], conversation: &str) {
        let Ok(frame) = serde_json::from_slice::<Frame>(line) else {
            return;
        };
        if frame.session_id.as_deref() != Some(conversation) {
            return;
        }
        match frame.kind.as_str() {
            // A subagent's replies run in their own context, not this one.
            "assistant" if frame.parent_tool_use_id.is_none() => {
                let Some(message) = frame.message else { return };
                let Some(usage) = message.usage else { return };
                let used = usage
                    .input_tokens
                    .saturating_add(usage.cache_creation_input_tokens)
                    .saturating_add(usage.cache_read_input_tokens);
                let window = self
                    .usage
                    .filter(|_| self.model.is_some() && self.model == message.model)
                    .and_then(|usage| usage.window);
                self.model = message.model;
                self.usage = Some(ContextUsage::now(used, window));
            }
            "result" => {
                let (Some(totals), Some(usage)) = (frame.model_usage, self.usage.as_mut()) else {
                    return;
                };
                let entry = match &self.model {
                    Some(model) if totals.contains_key(model) => totals.get(model),
                    _ if totals.len() == 1 => totals.values().next(),
                    _ => None,
                };
                if let Some(window) = entry.and_then(|entry| entry.context_window) {
                    usage.window = Some(window).filter(|size| *size > 0);
                }
            }
            _ => {}
        }
    }
}
