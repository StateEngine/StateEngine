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
        let (mut facts, mut over) = (Vec::new(), false);
        for (index, block) in blocks.iter().enumerate() {
            let Some(phase) = Self::phase(kind, block) else {
                continue;
            };
            let id = label(
                block.get(if phase == Phase::Called {
                    "id"
                } else {
                    "tool_use_id"
                }),
                256,
            );
            if !over && facts.len() == MAX_TOOLS_PER_RECORD {
                let r = UnknownReason::OverBudget;
                facts.pop();
                facts.push(Fact {
                    key: "claude/over-budget".into(),
                    native: NativeIdentity::Unknown(r),
                    phase,
                    tool: ToolName::Unknown(r),
                    target: Target::Unknown(r),
                    outcome: Outcome::Unknown(r),
                });
                over = true;
            }
            if over {
                if phase == Phase::Completed {
                    self.complete_call(
                        id.as_deref(),
                        block.get("is_error").and_then(Value::as_bool),
                    );
                }
                continue;
            }
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
                fact.target = if matches!(&fact.tool, ToolName::Known(n) if n == "Bash") {
                    super::targets::command(block.pointer("/input/command"))
                } else {
                    super::targets::arguments(block.get("input"), value.get("cwd"))
                };
                if let Some(id) = id {
                    self.record_call(id, block, &mut fact)?;
                }
            } else {
                let outcome = block.get("is_error").and_then(Value::as_bool);
                fact.outcome = match outcome {
                    Some(false) => Outcome::Succeeded,
                    Some(true) => Outcome::Failed,
                    None => Outcome::Unknown(UnknownReason::NoNativeOutcome),
                };
                if let Some(prior) = self.complete_call(id.as_deref(), outcome) {
                    (fact.tool, fact.target) = (prior.fact.tool.clone(), prior.fact.target.clone());
                    if prior.conflict {
                        conflict(&mut fact);
                    }
                }
            }
            facts.push(fact);
        }
        Ok(facts)
    }
    fn record_call(&mut self, id: String, block: &Value, fact: &mut Fact) -> Result<()> {
        let fp: [u8; 32] = Sha256::digest(serde_json::to_vec(block).map_err(json_error)?).into();
        if let Some(prior) = self.calls.iter_mut().find(|call| call.id == id) {
            prior.conflict |= prior.fingerprint != fp;
            if prior.conflict {
                conflict(fact);
            }
            return Ok(());
        }
        let bytes = serde_json::to_vec(&(&fact.native, &fact.tool, &fact.target))
            .map_err(json_error)?
            .len();
        while self.calls.len() >= MAX_CALLS || self.bytes.saturating_add(bytes) > MAX_STATE {
            let Some(at) = self.calls.iter().position(|c| c.result.is_some()) else {
                return Err(SeError::invalid(
                    "pending native tools",
                    "at most 1024 unresolved calls and 4 MiB; preserve the source cursor",
                ));
            };
            self.bytes -= self.calls.remove(at).map_or(0, |old| old.bytes);
        }
        self.bytes += bytes;
        self.calls.push_back(Call {
            id,
            fact: fact.clone(),
            fingerprint: fp,
            result: None,
            conflict: false,
            bytes,
        });
        Ok(())
    }
    fn complete_call(&mut self, id: Option<&str>, outcome: Option<bool>) -> Option<&Call> {
        let prior = id.and_then(|id| self.calls.iter_mut().find(|c| c.id == id))?;
        prior.conflict |= prior.result.is_some_and(|old| old != outcome);
        prior.result = Some(outcome);
        Some(prior)
    }
}
fn conflict(fact: &mut Fact) {
    let r = UnknownReason::ConflictingEvidence;
    (fact.tool, fact.target, fact.outcome) = (
        ToolName::Unknown(r),
        Target::Unknown(r),
        Outcome::Unknown(r),
    );
}
