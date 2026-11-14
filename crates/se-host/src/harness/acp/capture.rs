//! A sealed turn is still retained until its canonical messages are read back.
use super::*;
use crate::acp::{CompletedTurn, TurnItem};
use crate::harness::tool_capture::{self, Fact};
use se_core::ops::transcript::{Position, Record};
use se_store::Role;
use sha2::{Digest, Sha256};

pub(crate) struct Item {
    pub vendor: String,
    pub role: Role,
    pub bytes: Vec<u8>,
    pub facts: Vec<Fact>,
    text: Option<String>,
}
impl Item {
    pub fn body(&self, position: Position) -> Result<Body> {
        let kind = match &self.text {
            Some(text) if self.role != Role::System => return Body::new(text.clone()),
            Some(_) => "acp-interrupted-prefix",
            None => "acp-tool-update",
        };
        let mut record = Record::new(kind, None);
        record.message = self.text.clone();
        record.position = position;
        record.body()
    }
}
impl Binding {
    /// An interrupted prompt must survive independently of this live binding.
    /// Split the complete JSON on UTF-8 boundaries; no byte is truncated and
    /// every fragment stays below the canonical body's one-MiB limit.
    pub(crate) fn interrupted_items(&self) -> Result<Option<Vec<Item>>> {
        if self.interrupted_captured.load(Ordering::Acquire) {
            return Ok(Some(Vec::new()));
        }
        // Freeze before the first write. Late transport diagnostics must not
        // change an already committed fragment during a partial-write retry.
        let mut saved = self
            .interrupted_prefix
            .lock()
            .map_err(|_| error("interrupted capture state poisoned"))?;
        if saved.is_none() {
            let Some((key, prefix)) = self.session.interrupted_prefix()? else {
                return Ok(None);
            };
            *saved = Some((key, serde_json::to_string(&prefix).map_err(error)?));
        }
        let (key, payload) = saved
            .as_ref()
            .ok_or_else(|| error("original interrupted prefix absent"))?;
        let mut fragments = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let mut end = (offset + 64 * 1024).min(payload.len());
            while !payload.is_char_boundary(end) {
                end -= 1;
            }
            fragments.push(&payload[offset..end]);
            offset = end;
        }
        let key = se_types::hex_lower(&Sha256::digest(key.as_bytes()));
        let count = fragments.len();
        let items = fragments.into_iter().enumerate().map(|(part, fragment)| {
            let body = serde_json::to_string(&json!({
                "schema":"se.acp-interrupted-prefix-part/v1",
                "notice":"The native provider exited before this prompt completed. These observations are partial; input acceptance and a terminal reply are unproved.",
                "part":part,"parts":count,"fragment":fragment,
            })).map_err(error)?;
            Ok(Item {
                vendor: format!("{}acp/{key}/interrupted/{part}", se_store::TRANSCRIPT_EVENT_PREFIX),
                role: Role::System,
                bytes: body.as_bytes().to_vec(),
                facts: Vec::new(),
                text: Some(body),
            })
        }).collect::<Result<Vec<_>>>()?;
        Ok(Some(items))
    }
    pub(crate) fn acknowledge_interrupted(&self, end: u64) {
        self.capture_offset.store(end, Ordering::Release);
        self.interrupted_captured.store(true, Ordering::Release);
    }
    pub(crate) fn require_capture_settled(&self) -> Result<()> {
        let observed = self.session.observe()?;
        if !observed.completed.is_empty()
            || (observed.active_input.is_some()
                && !self.interrupted_captured.load(Ordering::Acquire))
        {
            return Err(error(
                "The observed protocol prefix still awaits durable capture. Preserve the original binding and resolve the reported capture failure before retrying stop for this agent.",
            ));
        }
        Ok(())
    }
    pub(crate) fn source(&self) -> Result<Vec<u8>> {
        self.incarnation
            .lock()
            .map_err(|_| error("source state poisoned"))?
            .clone()
            .ok_or_else(|| error("the initialized source binding is absent"))
    }
    pub(crate) fn offset(&self) -> u64 {
        self.capture_offset.load(Ordering::Acquire)
    }
    pub(crate) fn acknowledge(&self, request: u64, end: u64) -> Result<()> {
        self.session.acknowledge(request)?;
        self.capture_offset.store(end, Ordering::Release);
        Ok(())
    }
    pub(crate) fn items(&self, request: u64) -> Result<Vec<Item>> {
        let turn = self.session.completed(request)?;
        let mut items = vec![text(&turn, "input", Role::User, &turn.input)?];
        for item in &turn.order {
            match *item {
                TurnItem::Message { index } => {
                    let message = turn
                        .messages
                        .get(index)
                        .ok_or_else(|| error("sealed message index differs"))?;
                    items.push(text(
                        &turn,
                        &format!("message/{index}"),
                        Role::Assistant,
                        &message.text,
                    )?);
                }
                TurnItem::Tool { index } => {
                    let update = turn
                        .tools
                        .get(index)
                        .ok_or_else(|| error("sealed tool index differs"))?;
                    items.push(Item {
                        vendor: format!(
                            "{}acp/{}/tool/{index}",
                            se_store::TRANSCRIPT_EVENT_PREFIX,
                            se_types::hex_lower(&Sha256::digest(turn.input_key.as_bytes()))
                        ),
                        role: Role::System,
                        bytes: serde_json::to_vec(update).map_err(error)?,
                        facts: tool_capture::acp::facts(update, turn.request, &self.cwd)?,
                        text: None,
                    });
                }
            }
        }
        Ok(items)
    }
}
fn text(turn: &CompletedTurn, label: &str, role: Role, text: &str) -> Result<Item> {
    let vendor = format!(
        "acp/{}/{label}",
        se_types::hex_lower(&Sha256::digest(turn.input_key.as_bytes()))
    );
    let bytes = serde_json::to_vec(&json!({"input":turn.input_key,"item":label,"text":text}))
        .map_err(error)?;
    Ok(Item {
        vendor,
        role,
        bytes,
        facts: Vec::new(),
        text: Some(text.into()),
    })
}
