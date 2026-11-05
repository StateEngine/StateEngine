//! Trusted capture metadata contract, shared by native capture and derived consumers.
//! A tool intent is not an edit witness. Producers preserve native IDs and
//! explicit outcomes; consumers independently bind paths and content revisions.
//!
//! The pinned transcript reader emits these alongside capture progress, including
//! metadata-only batches. Bind identities from BoundTranscript, not native JSON.
//! Persist and advance together through existing capture metadata; no Atlas types
//! enter se-store and no new writer/IPC operation is introduced. Retain at most
//! the existing 32 metadata records per capture batch; never advance over a tool
//! fact that was not retained. Oversized target sets become Unknown(OverBudget),
//! preserving the exact raw source range instead of a silently shortened path set.
//!
//! Called and Completed are separate facts joined only by actual native identity
//! within one bound session/source. Missing or conflicting joins stay unknown.
//! Count adoption once per native call, never per path or replayed capture batch.
//! Deduplicate by session, source, provider, native identity, phase and source range;
//! unknown identities cannot support a claimed native-call count. Native result
//! ranges need not repeat intent targets: consumers may join known targets by ID.
//! Parse explicit native paths/queries only; never infer edits from shell text.
//!
//! Atlas may use successful exact paths as activity. To assert authorship of the
//! current content it must independently resolve that path within a registered
//! root and match an observed content digest to the indexed digest. Without that
//! witness, author remains unknown; opaque native revisions do not prove a match.
use super::Position;
use se_store::{Provider, RecordId, SourceEvidence};
use se_types::{AgentId, Result, SeError, SessionId};
use serde::{Deserialize, Serialize};
pub const SCHEMA: &str = "se.captured-tool/v1";
pub const MAX_BYTES: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UnknownReason {
    Pending,
    NoNativeIdentity,
    NoNativeTarget,
    NoNativeOutcome,
    UnmatchedIdentity,
    ConflictingEvidence,
    UnsupportedShape,
    OverBudget,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NativeIdentity {
    /// Claude tool_use.id and tool_result.tool_use_id, never a message UUID.
    ClaudeCall {
        tool_use_id: String,
    },
    /// Preserve actual Codex namespaces; an item ID is never relabelled call_id.
    CodexItem {
        turn_id: Option<String>,
        item_id: Option<String>,
        call_id: Option<String>,
    },
    Unknown(UnknownReason),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Phase {
    Called,
    Completed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Outcome {
    Succeeded,
    Failed,
    Cancelled,
    Unknown(UnknownReason),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedPath {
    /// Verbatim provider spelling; never resolve using the host's ambient cwd.
    pub spelling: String,
    /// Only an explicitly known native tool/thread cwd, otherwise None.
    pub cwd: Option<String>,
    /// Actual native post-tool content only, separately bound to this exact path.
    /// Never hash intended Write/Edit input and call it observed.
    pub content_revision: Option<ContentRevision>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Target {
    /// One native call may change several paths. Never silently trim this set.
    Paths(Vec<ObservedPath>),
    Query(String),
    /// Verbatim native shell text, or a lossless shell-quoted native argv.
    /// This describes execution only; never derive changed paths from it.
    Command(String),
    Unknown(UnknownReason),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ToolName {
    Known(String),
    Unknown(UnknownReason),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ContentRevision {
    /// Digests of actual post-tool bytes reported by the native producer.
    Sha256([u8; 32]),
    Blake3([u8; 32]),
    /// A native revision whose content-digest semantics are not established.
    Opaque {
        scheme: String,
        value: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: String,
    /// Both identities come from the authenticated capture binding, not JSON claims.
    pub session: SessionId,
    pub agent: AgentId,
    pub provider: Provider,
    pub source: RecordId,
    /// Exact native source range inside the enclosing committed SourceEvidence.
    pub position: Position,
    pub native: NativeIdentity,
    pub phase: Phase,
    pub tool: ToolName,
    pub target: Target,
    pub outcome: Outcome,
}
impl Observation {
    /// Call before committing each observation. CaptureRequest remains trusted
    /// host input; serializable durable metadata is not a new IPC write door.
    pub fn validate_binding(
        &self,
        session: &SessionId,
        agent: &AgentId,
        provider: Provider,
        source: RecordId,
        evidence: &SourceEvidence,
    ) -> Result<()> {
        if self.schema != SCHEMA
            || &self.session != session
            || &self.agent != agent
            || self.provider != provider
            || self.source != source
        {
            return Err(invalid(
                "the authenticated session, agent, provider and capture source",
            ));
        }
        if self.position.length == 0
            || self.position.offset < evidence.offset
            || self
                .position
                .offset
                .checked_add(self.position.length)
                .zip(evidence.offset.checked_add(evidence.length))
                .is_none_or(|(end, bound)| end > bound)
        {
            return Err(invalid(
                "a nonempty exact range within committed native source evidence",
            ));
        }
        match (&self.native, self.provider) {
            (NativeIdentity::ClaudeCall { tool_use_id }, Provider::Claude) => {
                label(tool_use_id, 256)?
            }
            (
                NativeIdentity::CodexItem {
                    turn_id,
                    item_id,
                    call_id,
                },
                Provider::Codex,
            ) => {
                if item_id.is_none() && call_id.is_none() {
                    return Err(invalid(
                        "a native item/call ID or explicitly unknown identity",
                    ));
                }
                for id in [turn_id, item_id, call_id].into_iter().flatten() {
                    label(id, 256)?;
                }
            }
            (NativeIdentity::Unknown(_), _) => (),
            _ => return Err(invalid("native identity namespace matching its provider")),
        }
        if self.phase == Phase::Called && !matches!(self.outcome, Outcome::Unknown(_)) {
            return Err(invalid(
                "a call intent with unknown outcome and no observed content revision",
            ));
        }
        if let ToolName::Known(name) = &self.tool {
            label(name, 128)?;
        }
        match &self.target {
            Target::Paths(paths) => {
                if paths.is_empty() || paths.len() > 16 {
                    return Err(invalid(
                        "one through sixteen observed paths or explicitly unknown target",
                    ));
                }
                for path in paths {
                    text(&path.spelling, 1024)?;
                    if self.phase == Phase::Called && path.content_revision.is_some() {
                        return Err(invalid("call intent without an observed content revision"));
                    }
                    if let Some(ContentRevision::Opaque { scheme, value }) = &path.content_revision
                    {
                        label(scheme, 64)?;
                        label(value, 256)?;
                    }
                    if let Some(cwd) = &path.cwd {
                        text(cwd, 1024)?;
                    }
                }
            }
            Target::Query(query) | Target::Command(query) => text(query, 1024)?,
            Target::Unknown(_) => (),
        }
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("serializable bounded observation"))?;
        if bytes.len() > MAX_BYTES {
            return Err(SeError::too_large(
                "captured tool observation",
                MAX_BYTES,
                bytes.len(),
            ));
        }
        Ok(())
    }
}
fn invalid(expected: &str) -> SeError {
    SeError::invalid("captured tool observation", expected)
}
fn text(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(invalid("nonempty, untruncated, bounded native text"));
    }
    Ok(())
}
fn label(value: &str, maximum: usize) -> Result<()> {
    text(value, maximum)?;
    if value.chars().any(char::is_control) {
        return Err(invalid("native identity/name without control characters"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use se_store::RecordIdentity;
    #[test]
    fn native_binding_and_intent_are_not_authorship() -> Result<()> {
        let session = SessionId::from_parts(1, [1; 10])?;
        let agent = AgentId::from_parts(1, [2; 10])?;
        let source =
            RecordId::from_parts(1, [3; 10]).map_err(|_| invalid("fixture source identity"))?;
        let evidence = SourceEvidence {
            path: None,
            incarnation: vec![1],
            offset: 10,
            length: 20,
            sha256: None,
        };
        let mut value = Observation {
            schema: SCHEMA.into(),
            session: session.clone(),
            agent: agent.clone(),
            provider: Provider::Claude,
            source,
            position: Position {
                offset: 10,
                length: 20,
            },
            native: NativeIdentity::ClaudeCall {
                tool_use_id: "toolu_native".into(),
            },
            phase: Phase::Called,
            tool: ToolName::Known("Edit".into()),
            target: Target::Paths(vec![ObservedPath {
                spelling: "src/file.rs".into(),
                cwd: None,
                content_revision: None,
            }]),
            outcome: Outcome::Unknown(UnknownReason::Pending),
        };
        let check = |v: &Observation| {
            v.validate_binding(&session, &agent, Provider::Claude, source, &evidence)
        };
        check(&value)?;
        value.outcome = Outcome::Succeeded;
        assert!(check(&value).is_err());
        value.phase = Phase::Completed;
        check(&value)?;
        value.provider = Provider::Codex;
        assert!(check(&value).is_err());
        value.provider = Provider::Claude;
        value.position.offset = u64::MAX;
        assert!(check(&value).is_err());
        value.position.offset = 10;
        value.target = Target::Paths(vec![ObservedPath {
            spelling: "src/file.rs".into(),
            cwd: None,
            content_revision: Some(ContentRevision::Sha256([7; 32])),
        }]);
        value.phase = Phase::Called;
        value.outcome = Outcome::Unknown(UnknownReason::Pending);
        assert!(check(&value).is_err());
        value.phase = Phase::Completed;
        value.outcome = Outcome::Succeeded;
        check(&value)
    }
}
