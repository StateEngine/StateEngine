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
    /// Opt-in producer age at response release. Add the measured release-to-flush
    /// span for an estimate without counting the long-poll wait. Independent
    /// machine suspend and clock-rate drift prevent a guaranteed upper bound.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub measure: bool,
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

/// Start an existing Owner-approved identity with its saved profile.
/// Work arrives through ordinary remote send after the returned session starts.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteLaunch {
    pub target: RemoteTarget,
    pub idempotency_key: IdempotencyKey,
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
        validate_body(&self.body)
    }
}
fn validate_body(body: &Body) -> Result<()> {
    if body.is_empty() {
        return Err(SeError::invalid("remote body", "nonempty UTF-8 text"));
    }
    if body.len() > MESSAGE_BODY_MAX_BYTES {
        return Err(SeError::too_large(
            "remote body",
            MESSAGE_BODY_MAX_BYTES,
            body.len(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteSendReply {
    pub source_message: crate::MessageId,
    pub target: RemoteTarget,
    pub reply_to: crate::MessageId,
    pub body: Body,
    pub idempotency_key: IdempotencyKey,
    pub kind: String,
    pub quiet: bool,
}
impl RemoteSendReply {
    pub fn validate(&self) -> Result<()> {
        validate_body(&self.body)?;
        if self.source_message.canonical_bytes()?.is_none()
            || self.idempotency_key.as_str() != format!("remote-reply-{}", self.source_message)
        {
            return Err(SeError::invalid(
                "remote reply identity",
                "the saved native source message ID and its original remote-reply key",
            ));
        }
        if !matches!(
            self.kind.as_str(),
            "note" | "task" | "question" | "answer" | "blocker" | "done" | "handoff" | "finding"
        ) {
            return Err(SeError::invalid(
                "remote reply kind",
                "an ordinary mail kind",
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
    Launch(RemoteLaunch),
    Reply(RemoteSendReply),
    Replies(RemoteReplies),
    ResolveContact(RemoteResolveContact),
}
impl RemoteRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::List(v) => v.validate(),
            Self::Watch(v) => v.validate(),
            Self::Send(v) => v.validate(),
            Self::Launch(_) => Ok(()),
            Self::Reply(v) => v.validate(),
            Self::Replies(v) => v.validate(),
            Self::ResolveContact(_) => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteResolveContact {
    pub target: RemoteTarget,
    pub original_grant: super::RemoteGrantId,
    pub idempotency_key: IdempotencyKey,
}

/// Return mail for this authenticated source address from one exact contact.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteReplies {
    pub target: RemoteTarget,
    pub after: Option<Cursor>,
    #[serde(default = "default_limit")]
    pub limit: u16,
    #[serde(default = "default_reply_budget")]
    pub budget: u32,
}
fn default_reply_budget() -> u32 {
    65536
}
impl RemoteReplies {
    pub fn validate(&self) -> Result<()> {
        if !(1..=20).contains(&self.limit)
            || !(49152..=REMOTE_REQUEST_BUDGET_BYTES as u32).contains(&self.budget)
        {
            return Err(SeError::invalid(
                "remote reply page",
                "1..20 messages and 49152..65536 encoded bytes",
            ));
        }
        Ok(())
    }
}

/// No caller actor, capability or Owner flag. Source is authenticated-broker attribution.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteInvocation {
    pub source: Option<RemoteSourceSession>,
    pub request: RemoteRequest,
}
