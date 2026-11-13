//! A streamed prefix is provisional. Only a terminal prompt response seals it.
use super::failure;
use se_types::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_TURN: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapturedMessage {
    pub role: String,
    pub text: String,
}
/// Chronology references bounded message/tool arrays without duplicating content.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnItem {
    Message { index: usize },
    Tool { index: usize },
}
/// A complete protocol turn, still awaiting host-owned durable capture.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletedTurn {
    pub request: u64,
    pub input_key: String,
    pub input: String,
    pub messages: Vec<CapturedMessage>,
    pub tools: Vec<Value>,
    pub order: Vec<TurnItem>,
    pub stop_reason: String,
}
#[derive(Clone)]
pub struct ProvisionalText {
    pub text: String,
    pub total_bytes: u64,
    pub omitted_bytes: u64,
}
pub(super) struct Turn {
    pub request: Option<u64>,
    pub input_key: String,
    pub input: String,
    pub messages: Vec<CapturedMessage>,
    pub tools: Vec<Value>,
    order: Vec<TurnItem>,
    statuses: BTreeMap<String, String>,
    bytes: usize,
    echo: String,
    last_message: Option<(String, Option<String>)>,
}
impl Turn {
    pub fn new(key: String, input: String) -> Result<Self> {
        if key.is_empty() || key.len() > 512 || input.is_empty() || input.len() > MAX_TURN {
            return Err(failure(
                "ACP input",
                "nonempty bounded identity and text required",
            ));
        }
        let bytes = input.len();
        Ok(Self {
            request: None,
            input_key: key,
            input,
            messages: Vec::new(),
            tools: Vec::new(),
            order: Vec::new(),
            statuses: BTreeMap::new(),
            bytes,
            echo: String::new(),
            last_message: None,
        })
    }
    pub fn preview(&self) -> ProvisionalText {
        let total = self.messages.iter().map(|m| m.text.len()).sum::<usize>();
        let mut skip = total.saturating_sub(8192);
        let mut text = String::new();
        for message in &self.messages {
            if skip >= message.text.len() {
                skip -= message.text.len();
                continue;
            }
            while !message.text.is_char_boundary(skip) {
                skip += 1;
            }
            text.push_str(&message.text[skip..]);
            skip = 0;
        }
        ProvisionalText {
            omitted_bytes: (total - text.len()) as u64,
            total_bytes: total as u64,
            text,
        }
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn update(&mut self, update: &Value) -> Result<()> {
        let kind = update
            .get("sessionUpdate")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("ACP update", "variant is absent"))?;
        match kind {
            "agent_message_chunk" | "user_message_chunk" => {
                let text = text(update.get("content"))?;
                if text.is_empty() {
                    return Ok(());
                }
                self.count(text.len())?;
                if kind == "user_message_chunk" {
                    self.echo.push_str(text);
                    if !self.input.starts_with(&self.echo) {
                        return Err(failure(
                            "ACP input echo",
                            "echo differs from original offered text",
                        ));
                    }
                    return Ok(());
                }
                let id = update
                    .get("messageId")
                    .map(|v| {
                        v.as_str()
                            .filter(|s| !s.is_empty() && s.len() <= 512)
                            .map(str::to_owned)
                            .ok_or_else(|| failure("ACP message", "invalid message identity"))
                    })
                    .transpose()?;
                let identity = ("assistant".to_owned(), id);
                if self.last_message.as_ref() == Some(&identity) {
                    self.messages
                        .last_mut()
                        .ok_or_else(|| failure("ACP message", "missing streamed message"))?
                        .text
                        .push_str(text);
                } else {
                    self.count(
                        std::mem::size_of::<CapturedMessage>()
                            + std::mem::size_of::<TurnItem>()
                            + "assistant".len(),
                    )?;
                    self.order.push(TurnItem::Message {
                        index: self.messages.len(),
                    });
                    self.messages.push(CapturedMessage {
                        role: "assistant".into(),
                        text: text.into(),
                    });
                    self.last_message = Some(identity);
                }
            }
            "agent_thought_chunk" => {
                // Reasoning is not a completed assistant message or a tool result.
                text(update.get("content"))?;
            }
            "tool_call" | "tool_call_update" => {
                let id = update
                    .get("toolCallId")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty() && v.len() <= 512)
                    .ok_or_else(|| failure("ACP tool", "bounded tool identity required"))?;
                let status = update.get("status").and_then(Value::as_str);
                if kind == "tool_call" {
                    if self.statuses.contains_key(id) {
                        return Err(failure("ACP tool", "duplicate tool creation"));
                    }
                    self.statuses
                        .insert(id.into(), status.unwrap_or("pending").into());
                } else {
                    let original = self
                        .statuses
                        .get_mut(id)
                        .ok_or_else(|| failure("ACP tool", "update has no original tool call"))?;
                    if let Some(status) = status {
                        *original = status.into();
                    }
                }
                if status.is_some_and(|s| {
                    !matches!(s, "pending" | "in_progress" | "completed" | "failed")
                }) {
                    return Err(failure("ACP tool", "unknown tool state"));
                }
                let bytes = serde_json::to_vec(update)
                    .map_err(|_| failure("ACP tool", "encoding failed"))?
                    .len();
                self.count(bytes)?;
                self.order.push(TurnItem::Tool {
                    index: self.tools.len(),
                });
                self.tools.push(update.clone());
                self.last_message = None;
            }
            "plan"
            | "available_commands_update"
            | "current_mode_update"
            | "config_option_update"
            | "session_info_update"
            | "usage_update" => {}
            _ => {
                return Err(failure(
                    "ACP capture",
                    "unsupported update; no complete prefix is claimed",
                ));
            }
        }
        Ok(())
    }
    fn count(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= MAX_TURN)
            .ok_or_else(|| {
                failure(
                    "ACP capture",
                    "eight-MiB turn bound exceeded; no prefix accepted",
                )
            })?;
        Ok(())
    }
    pub fn seal(&self, request: u64, result: &Value) -> Result<CompletedTurn> {
        let reason = result
            .get("stopReason")
            .and_then(Value::as_str)
            .filter(|s| {
                matches!(
                    *s,
                    "end_turn" | "max_tokens" | "max_turn_requests" | "refusal" | "cancelled"
                )
            })
            .ok_or_else(|| failure("ACP completion", "valid terminal stop reason required"))?;
        if self
            .statuses
            .values()
            .any(|s| !matches!(s.as_str(), "completed" | "failed"))
        {
            return Err(failure("ACP completion", "a tool call remains unsettled"));
        }
        if !self.echo.is_empty() && self.echo != self.input {
            return Err(failure(
                "ACP input echo",
                "only a partial original input was echoed",
            ));
        }
        Ok(CompletedTurn {
            request,
            input_key: self.input_key.clone(),
            input: self.input.clone(),
            messages: self.messages.clone(),
            tools: self.tools.clone(),
            order: self.order.clone(),
            stop_reason: reason.into(),
        })
    }
    /// Observations retained after native exit, without a protocol completion
    /// or an input-acceptance claim. Pending tool statuses stay unchanged.
    pub(super) fn interrupted_prefix(&self) -> Value {
        serde_json::json!({
            "schema": "se.acp-interrupted-prefix/v1",
            "terminal_reply": "absent",
            "request": self.request,
            "input_key": self.input_key,
            "offered_input": self.input,
            "input_echo": self.echo,
            "messages": self.messages,
            "tools": self.tools,
            "order": self.order,
        })
    }
}
pub(super) fn text(content: Option<&Value>) -> Result<&str> {
    let content = content.ok_or_else(|| failure("ACP text", "content is absent"))?;
    if content.get("type").and_then(Value::as_str) != Some("text") {
        return Err(failure(
            "ACP capture",
            "non-text content is unsupported; no complete prefix accepted",
        ));
    }
    content
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("ACP text", "text value is absent"))
}
