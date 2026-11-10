use super::{REMOTE_MAX_TARGETS, REMOTE_REQUEST_BUDGET_BYTES, RemoteSourceSession, RemoteTarget};
use crate::{Body, Cursor, IdempotencyKey, MESSAGE_BODY_MAX_BYTES, Result, SeError, SessionId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) fn validate_targets(targets: &[RemoteTarget], empty: bool) -> Result<()> {
    if (!empty && targets.is_empty())
        || targets.len() > REMOTE_MAX_TARGETS
        || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
    {
        return Err(SeError::invalid(
            "remote targets",
            "at most64 unique exact project/agent pairs",
        ));
    }
    Ok(())
}
fn default_limit() -> u16 {
    20
}
fn default_budget() -> u32 {
    32 * 1024
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteList {
    #[serde(default)]
    pub targets: Vec<RemoteTarget>,
    pub cursor: Option<Cursor>,
    #[serde(default = "default_limit")]
    pub limit: u16,
    #[serde(default = "default_budget")]
    pub budget: u32,
}
impl RemoteList {
    pub fn validate(&self) -> Result<()> {
        validate_targets(&self.targets, true)?;
        if !(1..=100).contains(&self.limit)
            || !(1024..=REMOTE_REQUEST_BUDGET_BYTES as u32).contains(&self.budget)
        {
            return Err(SeError::invalid(
                "remote list",
                "1..100 rows and1024..65536 encoded bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteCursorSet {
    pub target: RemoteTarget,
    pub durable: Option<Cursor>,
    pub live: Option<Cursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteWatch {
    #[serde(default)]
    pub targets: Vec<RemoteTarget>,
    #[serde(default)]
    pub cursors: Vec<RemoteCursorSet>,
    pub visible: Option<RemoteTarget>,
    #[serde(default = "default_budget")]
    pub budget: u32,
}
impl RemoteWatch {
    pub fn validate(&self) -> Result<()> {
        validate_targets(&self.targets, true)?;
        let cursor_targets: Vec<_> = self.cursors.iter().map(|c| c.target.clone()).collect();
        validate_targets(&cursor_targets, true)?;
        if !(1024..=REMOTE_REQUEST_BUDGET_BYTES as u32).contains(&self.budget)
            || self
                .visible
                .as_ref()
                .is_some_and(|v| !self.targets.is_empty() && !self.targets.contains(v))
            || self
                .cursors
                .iter()
                .any(|c| !self.targets.is_empty() && !self.targets.contains(&c.target))
        {
            return Err(SeError::invalid(
                "remote watch",
                "bounded output and cursors/visible target in the selected set",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteSend {
    pub target: RemoteTarget,
    pub session: SessionId,
    pub body: Body,
    pub idempotency_key: IdempotencyKey,
}
impl RemoteSend {
    pub fn validate(&self) -> Result<()> {
        if self.body.is_empty() {
            return Err(SeError::invalid("remote body", "nonempty UTF-8 text"));
        }
        if self.body.len() > MESSAGE_BODY_MAX_BYTES {
            return Err(SeError::too_large(
                "remote body",
                MESSAGE_BODY_MAX_BYTES,
                self.body.len(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "operation",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RemoteRequest {
    List(RemoteList),
    Watch(RemoteWatch),
    Send(RemoteSend),
}
impl RemoteRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::List(v) => v.validate(),
            Self::Watch(v) => v.validate(),
            Self::Send(v) => v.validate(),
        }
    }
}

/// No caller actor, capability or Owner flag. Source is authenticated-broker attribution.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteInvocation {
    pub source: Option<RemoteSourceSession>,
    pub request: RemoteRequest,
}
