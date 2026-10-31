//! The closed wave-one DTOs. Surface adapters supply authority and entropy separately.
use crate::commit::{MessageSend, WorkingStateSet};
use crate::config_policy::Provider;
use schemars::JsonSchema;
use se_types::{
    Cursor, Detail, IdempotencyKey, MESSAGE_BODY_MAX_BYTES, Result, SeError,
    WORKING_STATE_MAX_BYTES, details,
};
use serde::{Deserialize, Serialize};

pub trait Validate {
    fn validate(&self) -> Result<()>;
}
pub fn bounded(field: &str, value: &str, maximum: usize, allow_empty: bool) -> Result<()> {
    if value.len() > maximum {
        return Err(SeError::too_large(field, maximum, value.len()));
    }
    if value.contains('\0') || (!allow_empty && value.is_empty()) {
        return Err(SeError::invalid(field, "bounded UTF-8 text without NUL"));
    }
    Ok(())
}
pub fn name(field: &str, value: &str) -> Result<()> {
    bounded(field, value, 64, false)?;
    if !value
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b))
    {
        return Err(SeError::invalid(
            field,
            "1..64 ASCII name characters, starting with a letter or digit",
        ));
    }
    Ok(())
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetaVersion {}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetaHelp {
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub all: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetaSchema {
    pub op: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectInit {
    pub repo: Option<String>,
    pub name: Option<String>,
    #[serde(default = "main_agent")]
    pub agent: String,
    pub provider: Option<Provider>,
    pub model: Option<String>,
    #[serde(default)]
    pub launch: bool,
    #[serde(default)]
    pub adopt: bool,
    pub idempotency_key: IdempotencyKey,
}
fn main_agent() -> String {
    "main".into()
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectStatus {
    #[serde(skip)]
    #[schemars(skip)]
    pub all: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkingStateGet {
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_agent: Option<se_types::AgentId>,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MessageView {
    #[default]
    Unread,
    All,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MessageBox {
    #[default]
    Inbox,
    Sent,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageList {
    #[serde(default)]
    pub view: MessageView,
    #[serde(default, rename = "box")]
    pub mailbox: MessageBox,
    pub from: Option<String>,
    pub kind: Option<crate::commit::MessageKind>,
    #[serde(default)]
    pub full: bool,
    #[serde(default = "page_limit")]
    pub limit: u16,
    pub preview_chars: Option<u16>,
    pub cursor: Option<Cursor>,
    #[serde(skip)]
    #[schemars(skip)]
    pub owner_to: Option<String>,
}
fn page_limit() -> u16 {
    20
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUp {
    #[serde(default)]
    pub foreground: bool,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDown {
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Uninstall {
    pub idempotency_key: IdempotencyKey,
}

impl Validate for MetaVersion {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
impl Validate for MetaHelp {
    fn validate(&self) -> Result<()> {
        if self.path.len() > 8 {
            return Err(SeError::invalid(
                "help path",
                "at most eight registered command components",
            ));
        }
        for part in &self.path {
            bounded("help path", part, 64, false)?;
        }
        Ok(())
    }
}
impl Validate for MetaSchema {
    fn validate(&self) -> Result<()> {
        if let Some(op) = &self.op {
            bounded("operation", op, 128, false)?;
        }
        Ok(())
    }
}
impl Validate for ProjectStatus {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
impl Validate for WorkingStateGet {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
impl Validate for ProjectInit {
    fn validate(&self) -> Result<()> {
        if let Some(repo) = &self.repo {
            bounded("repo", repo, 32768, false)?;
        }
        if let Some(value) = &self.name {
            name("name", value)?;
        }
        name("agent", &self.agent)?;
        if let Some(model) = &self.model {
            bounded("model", model, 128, false)?;
        }
        Ok(())
    }
}
impl Validate for MessageSend {
    fn validate(&self) -> Result<()> {
        bounded("to", &self.to, 512, false)?;
        bounded("body", &self.body, MESSAGE_BODY_MAX_BYTES, false)?;
        if self.refs.len() > 20 {
            return Err(SeError::invalid("refs", "at most 20 event ids"));
        }
        for reference in &self.refs {
            se_types::EventId::from_legacy(reference.clone())?;
        }
        Ok(())
    }
}
impl Validate for WorkingStateSet {
    fn validate(&self) -> Result<()> {
        bounded("text", &self.text, WORKING_STATE_MAX_BYTES, true)?;
        if matches!(self.expect, crate::commit::ExpectedRevision::Revision(0)) {
            return Err(SeError::invalid(
                "expect",
                "a positive entity revision or absent",
            ));
        }
        Ok(())
    }
}
impl Validate for MessageList {
    fn validate(&self) -> Result<()> {
        if !(1..=100).contains(&self.limit) {
            return Err(SeError::invalid("limit", "1..100"));
        }
        if self.preview_chars.is_some_and(|n| n > 4000) {
            return Err(SeError::invalid("preview_chars", "0..4000"));
        }
        if self.full && self.preview_chars.is_some() {
            return Err(SeError::new(Detail::UsageConflictingFlags(
                details::UsageConflictingFlags {
                    flags: vec!["full".into(), "preview_chars".into()],
                },
            )));
        }
        if let Some(from) = &self.from {
            bounded("from", from, 512, false)?;
        }
        if let Some(to) = &self.owner_to {
            bounded("to", to, 512, false)?;
        }
        Ok(())
    }
}
macro_rules! keyed { ($($ty:ty),+) => { $(impl Validate for $ty { fn validate(&self)->Result<()> { Ok(()) } })+ }; }
keyed!(RuntimeUp, RuntimeDown, Uninstall);
