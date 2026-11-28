//! `session.publish_turn`: a harness or owner client records a completed turn
//! without terminal scraping. Prose (body text, decision, changed paths) is one
//! erasable body; usage, counts and identities stay as structure after forget.
use crate::{commit::Cx, dispatch::Kernel, ops::inputs::Validate, scope};

type Step = crate::commit::OpStep<super::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>;
use schemars::JsonSchema;
use se_store::{
    Actor, EventBody, InputText, Role, Snapshot,
    published_turn::{DiffCounts, PublishedTurn, TurnNesting, TurnUsage},
};
use se_types::{AgentId, IdempotencyKey, Result, SeError, SessionId, WriteReceipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_PROSE_BYTES: usize = 1024 * 1024;
const MAX_PATHS: usize = 256;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublishedRole {
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishedModel {
    /// Model provider, such as the vendor whose API served the turn.
    pub provider: String,
    pub model: String,
}

/// Token counts the harness reported. Include `cost_usd` only when the harness
/// reported a cost; StateEngine never estimates one.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishedUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub cache_read_tokens: u64,
    #[serde(default)]
    pub cache_write_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishedDiff {
    pub files_changed: u64,
    pub insertions: u64,
    pub deletions: u64,
    /// Changed paths, at most 256. They are erased with the body on forget.
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishedDecision {
    pub title: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub scope: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishedNesting {
    /// The StateEngine session this nested turn ran under.
    pub parent_session_id: SessionId,
    /// The harness's own label for the nested agent.
    pub nested_agent_id: String,
    /// 1 for a direct child, at most 64.
    pub depth: u32,
}

/// One completed turn. A bound session publishes for itself: `session_id` and
/// `target_agent_id` may be omitted and must match it when given. The owner
/// names both.
/// The operation input, boxed so it does not widen every operation value.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionPublishTurn(pub Box<PublishTurnRequest>);
/// Tools advertise the request object itself, not a reference to it.
impl JsonSchema for SessionPublishTurn {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        PublishTurnRequest::schema_name()
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        PublishTurnRequest::json_schema(generator)
    }
}
impl std::ops::Deref for SessionPublishTurn {
    type Target = PublishTurnRequest;
    fn deref(&self) -> &PublishTurnRequest {
        &self.0
    }
}
impl std::ops::DerefMut for SessionPublishTurn {
    fn deref_mut(&mut self) -> &mut PublishTurnRequest {
        &mut self.0
    }
}
impl Validate for SessionPublishTurn {
    fn validate(&self) -> Result<()> {
        self.0.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishTurnRequest {
    pub idempotency_key: IdempotencyKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// The harness's own conversation ID.
    pub conversation_id: String,
    /// The harness name, such as the program that ran the turn.
    pub harness: String,
    pub model: PublishedModel,
    /// The harness's ID for this turn; one per session and harness.
    pub vendor_turn_id: String,
    /// When the turn completed, in Unix microseconds.
    pub occurred_at_us: i64,
    pub role: PublishedRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_text: Option<String>,
    /// Bytes of the original body left out of `body_text`.
    #[serde(default)]
    pub body_omitted_bytes: u64,
    /// Lowercase hex SHA-256 of the complete UTF-8 body. It is checked when the
    /// whole body is supplied and recorded as reported otherwise. It is kept only
    /// when prose is stored, so `se forget` can erase the two together.
    pub content_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<PublishedUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_summary: Option<PublishedDiff>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<PublishedDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nesting: Option<PublishedNesting>,
}

fn bounded(field: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(SeError::invalid(
            field,
            &format!("1 to {max} bytes without control characters"),
        ));
    }
    Ok(())
}

fn digest(hex: &str) -> Result<[u8; 32]> {
    let invalid = || SeError::invalid("content_sha256", "64 lowercase hex characters");
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

impl Validate for PublishTurnRequest {
    fn validate(&self) -> Result<()> {
        bounded("conversation_id", &self.conversation_id, 256)?;
        bounded("harness", &self.harness, 64)?;
        bounded("model.provider", &self.model.provider, 64)?;
        bounded("model.model", &self.model.model, 128)?;
        bounded("vendor_turn_id", &self.vendor_turn_id, 256)?;
        if self.occurred_at_us < 0 {
            return Err(SeError::invalid(
                "occurred_at_us",
                "Unix microseconds, not negative",
            ));
        }
        digest(&self.content_sha256)?;
        if self
            .body_text
            .as_ref()
            .is_some_and(|t| t.len() > MAX_PROSE_BYTES)
        {
            return Err(SeError::invalid(
                "body_text",
                "at most 1 MiB; send a shorter body and report body_omitted_bytes",
            ));
        }
        if self.body_omitted_bytes > i64::MAX as u64 {
            return Err(SeError::invalid(
                "body_omitted_bytes",
                "a representable byte count",
            ));
        }
        if let Some(usage) = &self.usage {
            let counts = [
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_tokens,
                usage.cache_write_tokens,
            ];
            if counts.iter().any(|n| *n > i64::MAX as u64)
                || usage
                    .cost_usd
                    .is_some_and(|c| !c.is_finite() || c.is_sign_negative())
            {
                return Err(SeError::invalid(
                    "usage",
                    "representable token counts and a finite, non-negative cost_usd",
                ));
            }
        }
        if let Some(diff) = &self.diff_summary {
            if [diff.files_changed, diff.insertions, diff.deletions]
                .iter()
                .any(|n| *n > i64::MAX as u64)
            {
                return Err(SeError::invalid("diff_summary", "representable counts"));
            }
            if diff.paths.len() > MAX_PATHS {
                return Err(SeError::invalid("diff_summary.paths", "at most 256 paths"));
            }
            for path in &diff.paths {
                bounded("diff_summary.paths", path, 4096)?;
            }
        }
        if let Some(decision) = &self.decision {
            bounded("decision.title", &decision.title, 256)?;
            if decision.rationale.len() > 16 * 1024 || decision.scope.len() > 256 {
                return Err(SeError::invalid(
                    "decision",
                    "a rationale within 16 KiB and a scope within 256 bytes",
                ));
            }
        }
        if let Some(nesting) = &self.nesting {
            bounded("nesting.nested_agent_id", &nesting.nested_agent_id, 256)?;
            if !(1..=64).contains(&nesting.depth) {
                return Err(SeError::invalid("nesting.depth", "1 to 64"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SessionPublishTurnOutput {
    pub agent_id: AgentId,
    pub session_id: SessionId,
    pub vendor_turn_id: String,
    /// The store sequence of the published event, usable as a history cursor.
    pub cursor: u64,
    /// Whether a prose body was stored.
    pub body_stored: bool,
    /// Whether `content_sha256` was kept; it is kept only beside stored prose.
    pub content_sha256_stored: bool,
    /// True when the stored body is complete and matched `content_sha256`.
    pub content_verified: bool,
    pub commit: WriteReceipt,
}

pub struct PublishTurnThen {
    key: IdempotencyKey,
}

/// The one prose document: everything `se forget` must be able to remove.
fn prose(input: &PublishTurnRequest) -> Result<Option<String>> {
    let mut doc = serde_json::Map::new();
    if let Some(text) = &input.body_text {
        doc.insert("text".into(), text.clone().into());
    }
    if let Some(decision) = &input.decision {
        doc.insert(
            "decision".into(),
            serde_json::json!({"title":decision.title,"rationale":decision.rationale,"scope":decision.scope}),
        );
    }
    if let Some(diff) = input.diff_summary.as_ref().filter(|d| !d.paths.is_empty()) {
        doc.insert("paths".into(), serde_json::json!(diff.paths));
    }
    if doc.is_empty() {
        return Ok(None);
    }
    let text = serde_json::Value::Object(doc).to_string();
    if text.len() > MAX_PROSE_BYTES {
        return Err(SeError::invalid(
            "body_text",
            "body, decision and paths together within 1 MiB; send a shorter body and report body_omitted_bytes",
        ));
    }
    Ok(Some(text))
}

/// Who the turn belongs to: a session only ever names itself.
fn subject<R: Snapshot>(
    input: &PublishTurnRequest,
    cx: &Cx<'_, R>,
) -> Result<(AgentId, SessionId)> {
    match (&cx.admission.actor, &cx.admission.session) {
        (Actor::Agent(actor), Some(bound)) => {
            if input.target_agent_id.as_ref().is_some_and(|a| a != actor)
                || input.session_id.as_ref().is_some_and(|s| s != bound)
            {
                return Err(SeError::invalid(
                    "session_id",
                    "your own bound agent and session; a session cannot publish another session's turns",
                ));
            }
            Ok((actor.clone(), bound.clone()))
        }
        (Actor::Human(_), None) => match (&input.target_agent_id, &input.session_id) {
            (Some(agent), Some(session)) => Ok((agent.clone(), session.clone())),
            _ => Err(SeError::invalid(
                "target_agent_id",
                "both target_agent_id and session_id when the owner publishes a turn",
            )),
        },
        _ => Err(scope::unreadable(
            "publish turn admission",
            "actor and session binding disagree",
        )),
    }
}

pub fn write<R: Snapshot>(
    kernel: &Kernel,
    input: SessionPublishTurn,
    cx: &mut Cx<'_, R>,
) -> Result<Step> {
    let input = *input.0;
    input.validate()?;
    scope::project(cx.admission)?;
    let (agent, session) = subject(&input, cx)?;
    let reported = digest(&input.content_sha256)?;
    let content_verified = match &input.body_text {
        Some(text) if input.body_omitted_bytes == 0 => {
            if Sha256::digest(text.as_bytes()).as_slice() != reported {
                return Err(SeError::invalid(
                    "content_sha256",
                    "the SHA-256 of body_text when the whole body is supplied; recompute it or report body_omitted_bytes",
                ));
            }
            true
        }
        _ => false,
    };
    let body = prose(&input)?;
    let role = match input.role {
        PublishedRole::User => Role::User,
        PublishedRole::Assistant => Role::Assistant,
        PublishedRole::Tool => Role::Tool,
    };
    let turn = PublishedTurn {
        agent,
        session,
        conversation: input.conversation_id.clone(),
        harness: input.harness.clone(),
        model_provider: input.model.provider.clone(),
        model: input.model.model.clone(),
        vendor_turn: input.vendor_turn_id.clone(),
        occurred_at_us: input.occurred_at_us,
        role,
        body_omitted_bytes: input.body_omitted_bytes,
        content_sha256: body.as_ref().map(|_| reported),
        content_verified,
        usage: input.usage.as_ref().map(|u| TurnUsage {
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            cache_read_tokens: u.cache_read_tokens,
            cache_write_tokens: u.cache_write_tokens,
            cost_usd: u.cost_usd,
        }),
        diff: input.diff_summary.as_ref().map(|d| DiffCounts {
            files_changed: d.files_changed,
            insertions: d.insertions,
            deletions: d.deletions,
        }),
        nesting: input.nesting.as_ref().map(|n| TurnNesting {
            parent_session: n.parent_session_id.clone(),
            nested_agent: n.nested_agent_id.clone(),
            depth: n.depth,
        }),
    };
    let key = input.idempotency_key.clone();
    let intent = serde_json::to_value(&input)
        .map_err(|e| SeError::invalid("publish turn", &e.to_string()))?;
    let event = kernel.event(
        EventBody::SessionTurnPublished {
            turn,
            body: body.map(InputText::Inline),
        },
        cx,
    )?;
    let batch = kernel.batch("session.publish_turn", key.clone(), intent, event, cx)?;
    Ok(crate::commit::OpStep::Commit {
        batch,
        then: crate::ports::Then::PublishTurn(PublishTurnThen { key }),
    })
}

pub fn committed<R: Snapshot>(
    then: PublishTurnThen,
    receipt: se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::AnyOutput> {
    super::receipt::receipt_key(&receipt, &then.key, "publish turn receipt")?;
    let primary = super::receipt::committed_event(cx.read, &receipt)?;
    let commit = super::receipt::write_fields(&receipt, &primary)?;
    if primary.header.scope != cx.admission.scope || primary.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "committed published turn",
            "receipt resolved outside the admitted scope/actor",
        ));
    }
    let EventBody::SessionTurnPublished { turn, body } = primary.body else {
        return Err(scope::unreadable(
            "publish turn receipt",
            "primary event is not session.turn_published",
        ));
    };
    Ok(SessionPublishTurnOutput {
        agent_id: turn.agent,
        session_id: turn.session,
        vendor_turn_id: turn.vendor_turn,
        cursor: receipt.first.sequence(),
        body_stored: body.is_some(),
        content_sha256_stored: turn.content_sha256.is_some(),
        content_verified: turn.content_verified,
        commit,
    }
    .into())
}
