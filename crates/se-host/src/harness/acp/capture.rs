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
        if let Some(text) = &self.text {
            return Body::new(text.clone());
        }
        let mut record = Record::new("acp-tool-update", None);
        record.position = position;
        record.body()
    }
}
impl Binding {
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
