//! Join only real tool_use.id/tool_result.tool_use_id in one pinned source.
use super::*;
use serde_json::Value;
use std::collections::VecDeque;

const MAX_CALLS: usize = 1024;
const MAX_STATE: usize = 4 * 1024 * 1024;
pub const MAX_TOOLS_PER_RECORD: usize = 32;
#[derive(Clone, Default)]
pub struct Tracker {
    calls: VecDeque<Call>,
    bytes: usize,
}
#[derive(Clone)]
struct Call {
    id: String,
    fact: Fact,
    fingerprint: [u8; 32],
    completed: bool,
    result: Option<Option<bool>>,
    conflict: bool,
    bytes: usize,
}
impl Tracker {
    fn blocks(value: &Value) -> Option<(&str, &[Value])> {
        let kind = value.get("type").and_then(Value::as_str)?;
        if !matches!(kind, "user" | "assistant")
            || value.get("isSidechain").and_then(Value::as_bool) == Some(true)
            || value.pointer("/message/model").and_then(Value::as_str) == Some("<synthetic>")
        {
            return None;
        }
        Some((kind, value.pointer("/message/content")?.as_array()?))
    }
    fn phase(kind: &str, block: &Value) -> Option<Phase> {
        match (kind, block.get("type").and_then(Value::as_str)) {
            ("assistant", Some("tool_use")) => Some(Phase::Called),
            ("user", Some("tool_result")) => Some(Phase::Completed),
            _ => None,
        }
    }
    pub fn count(value: &Value) -> usize {
        Self::blocks(value).map_or(0, |(k, b)| {
            b.iter()
                .filter(|x| Self::phase(k, x).is_some())
                .count()
                .min(MAX_TOOLS_PER_RECORD)
        })
    }
    pub fn observe(&mut self, value: &Value) -> Result<Vec<Fact>> {
        let Some((kind, blocks)) = Self::blocks(value) else {
            return Ok(Vec::new());
        };
        let mut facts = Vec::new();
        for (index, block) in blocks.iter().enumerate() {
            let Some(phase) = Self::phase(kind, block) else {
                continue;
            };
            if facts.len() == MAX_TOOLS_PER_RECORD {
                facts.pop();
                facts.push(Fact {
                    key: "claude/over-budget".into(),
                    native: NativeIdentity::Unknown(UnknownReason::OverBudget),
                    phase,
                    tool: ToolName::Unknown(UnknownReason::OverBudget),
                    target: Target::Unknown(UnknownReason::OverBudget),
                    outcome: Outcome::Unknown(UnknownReason::OverBudget),
                });
                break;
            }
            let id = label(
                block.get(if phase == Phase::Called {
                    "id"
                } else {
                    "tool_use_id"
                }),
                256,
            );
            facts.push(self.build_fact(value, index, block, id, phase)?);
        }
        Ok(facts)
    }
    fn build_fact(
        &mut self,
        value: &Value,
        index: usize,
        block: &Value,
        id: Option<String>,
        phase: Phase,
    ) -> Result<Fact> {
        let mut fact = Fact {
            key: format!("claude/{index}"),
            native: id.clone().map_or(
                NativeIdentity::Unknown(UnknownReason::NoNativeIdentity),
                |tool_use_id| NativeIdentity::ClaudeCall { tool_use_id },
            ),
            phase,
            tool: ToolName::Unknown(UnknownReason::UnmatchedIdentity),
            target: Target::Unknown(UnknownReason::UnmatchedIdentity),
            outcome: Outcome::Unknown(UnknownReason::Pending),
        };
        if phase == Phase::Called {
            fact.tool = tool(block.get("name"));
            fact.target = if matches!(&fact.tool, ToolName::Known(name) if name == "Bash") {
                super::targets::command(block.pointer("/input/command"))
            } else {
                super::targets::arguments(block.get("input"), value.get("cwd"))
            };
            if let Some(id) = id {
                let fingerprint: [u8; 32] =
                    Sha256::digest(serde_json::to_vec(block).map_err(json_error)?).into();
                if let Some(prior) = self.calls.iter_mut().find(|call| call.id == id) {
                    prior.conflict |= prior.fingerprint != fingerprint;
                    if prior.conflict {
                        conflict(&mut fact);
                    }
                } else {
                    let bytes = serde_json::to_vec(&(&fact.native, &fact.tool, &fact.target))
                        .map_err(json_error)?
                        .len();
                    while self.calls.len() >= MAX_CALLS
                        || self.bytes.saturating_add(bytes) > MAX_STATE
                    {
                        let Some(index) = self.calls.iter().position(|call| call.completed) else {
                            return Err(SeError::invalid(
                                "pending native tools",
                                "at most 1024 unresolved calls and 4 MiB; preserve the source cursor",
                            ));
                        };
                        if let Some(old) = self.calls.remove(index) {
                            self.bytes -= old.bytes;
                        }
                    }
                    self.bytes += bytes;
                    self.calls.push_back(Call {
                        id,
                        fact: fact.clone(),
                        fingerprint,
                        completed: false,
                        result: None,
                        conflict: false,
                        bytes,
                    });
                }
            }
        } else {
            let outcome = block.get("is_error").and_then(Value::as_bool);
            fact.outcome = match outcome {
                Some(false) => Outcome::Succeeded,
                Some(true) => Outcome::Failed,
                None => Outcome::Unknown(UnknownReason::NoNativeOutcome),
            };
            if let Some(id) = id
                && let Some(prior) = self.calls.iter_mut().find(|call| call.id == id)
            {
                prior.conflict |= prior.result.is_some_and(|old| old != outcome);
                prior.result = Some(outcome);
                prior.completed = true;
                fact.tool = prior.fact.tool.clone();
                fact.target = prior.fact.target.clone();
                if prior.conflict {
                    conflict(&mut fact);
                }
            }
        }
        Ok(fact)
    }
}
fn conflict(fact: &mut Fact) {
    fact.tool = ToolName::Unknown(UnknownReason::ConflictingEvidence);
    fact.target = Target::Unknown(UnknownReason::ConflictingEvidence);
    fact.outcome = Outcome::Unknown(UnknownReason::ConflictingEvidence);
}
