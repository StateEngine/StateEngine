//! Closed source-client commands. Remote targets never select a local project.
use super::inputs::{Validate, bounded};
use schemars::JsonSchema;
use se_types::{Result, SeError, remote::*};
use serde::{Deserialize, Serialize};

pub fn validate_alias(host: &str) -> Result<()> {
    bounded("remote host alias", host, 64, false)?;
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SeError::invalid(
            "remote host alias",
            "1..64 ASCII letters, digits, hyphens or underscores from an Owner-configured binding",
        ));
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteListCall {
    pub host: String,
    pub request: RemoteList,
}
impl Validate for RemoteListCall {
    fn validate(&self) -> Result<()> {
        validate_alias(&self.host)?;
        self.request.validate()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteWatchCall {
    pub host: String,
    pub request: RemoteWatch,
    /// Non-authoritative source-side reader partition; absent keeps legacy reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader_id: Option<[u8; 16]>,
    #[serde(default)]
    pub wait_ms: u32,
    #[serde(skip)]
    #[schemars(skip)]
    pub follow: bool,
}
impl Validate for RemoteWatchCall {
    fn validate(&self) -> Result<()> {
        validate_alias(&self.host)?;
        self.request.validate()?;
        if self.wait_ms > 30_000 {
            return Err(SeError::invalid("remote wait_ms", "0..30000 milliseconds"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteSendCall {
    pub host: String,
    pub request: RemoteSend,
    /// Optional replay precondition, never authority or a new key selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_binding: Option<Box<RemoteBindingSelection>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteBindingSelection {
    pub host: RemoteHostId,
    pub grant: se_types::RemoteGrantId,
}
impl Validate for RemoteSendCall {
    fn validate(&self) -> Result<()> {
        validate_alias(&self.host)?;
        self.request.validate()
    }
}

// The local envelope owns the schema; wire and local consumers share each body.
pub use se_types::remote::{
    RemoteListBody as RemoteListOutput, RemoteSendBody as RemoteSendOutput,
    RemoteWatchBody as RemoteWatchOutput,
};

/// Internal source IPC only: obtain the nonsecret binding facts after native
/// admission, before the CLI emits its pending row. No target request or mutation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemotePrepareSendCall {
    pub host: String,
    pub request: RemoteSend,
}
impl Validate for RemotePrepareSendCall {
    fn validate(&self) -> Result<()> {
        validate_alias(&self.host)?;
        self.request.validate()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemoteSendPreparation {
    pub host: RemoteHostId,
    pub grant: se_types::RemoteGrantId,
    pub target: RemoteTarget,
    pub session: se_types::SessionId,
    pub idempotency_key: se_types::IdempotencyKey,
    pub body_bytes: u32,
}
