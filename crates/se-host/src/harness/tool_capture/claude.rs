//! Join only real tool_use.id/tool_result.tool_use_id in one pinned source.
use super::*;
use serde_json::Value;
use std::collections::VecDeque;

const MAX_CALLS: usize = 1024;
const MAX_STATE: usize = 4 * 1024 * 1024;
#[derive(Clone, Default)]
pub(crate) struct Tracker {
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
    pub fn count(value: &Value) -> usize {
        if value.get("isSidechain").and_then(Value::as_bool) == Some(true)
            || value.pointer("/message/model").and_then(Value::as_str) == Some("<synthetic>")
        {
            return 0;
        }
        let kind = value.get("type").and_then(Value::as_str);
        value
            .pointer("/message/content")
            .and_then(Value::as_array)
            .map_or(0, |blocks| {
                blocks
                    .iter()
                    .filter(|b| {
                        matches!(
                            (kind, b.get("type").and_then(Value::as_str)),
                            (Some("assistant"), Some("tool_use"))
                                | (Some("user"), Some("tool_result"))
                        )
                    })
                    .count()
            })
    }
    pub fn observe(&mut self, value: &Value) -> Result<Vec<Fact>> {
        let kind = value.get("type").and_then(Value::as_str);
        if !matches!(kind, Some("user" | "assistant"))
            || value.get("isSidechain").and_then(Value::as_bool) == Some(true)
            || value.pointer("/message/model").and_then(Value::as_str) == Some("<synthetic>")
        {
            return Ok(Vec::new());
        }
        let Some(blocks) = value.pointer("/message/content").and_then(Value::as_array) else {
            return Ok(Vec::new());
        };
        let mut facts = Vec::new();
        for (index, block) in blocks.iter().enumerate() {
            let phase = match (kind, block.get("type").and_then(Value::as_str)) {
                (Some("assistant"), Some("tool_use")) => Phase::Called,
                (Some("user"), Some("tool_result")) => Phase::Completed,
                _ => continue,
            };
            if facts.len() == 32 {
                return Err(SeError::invalid(
                    "native tools per record",
                    "at most 32 tool facts; preserve the source cursor",
                ));
            }
            let id = label(
                block.get(if phase == Phase::Called {
                    "id"
                } else {
                    "tool_use_id"
                }),
                256,
            );
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
                fact.target = super::targets::arguments(block.get("input"), value.get("cwd"));
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
                            let Some(index) = self.calls.iter().position(|call| call.completed)
                            else {
                                return Err(SeError::invalid(
                                    "pending native tools",
                                    "at most 1024 unresolved calls and 4 MiB; preserve the source cursor",
                                ));
                            };
                            let old = self.calls.remove(index).ok_or_else(|| {
                                SeError::invalid(
                                    "native tool cache",
                                    "the selected completed entry",
                                )
                            })?;
                            self.bytes -= old.bytes;
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
            facts.push(fact);
        }
        Ok(facts)
    }
}
fn conflict(fact: &mut Fact) {
    fact.tool = ToolName::Unknown(UnknownReason::ConflictingEvidence);
    fact.target = Target::Unknown(UnknownReason::ConflictingEvidence);
    fact.outcome = Outcome::Unknown(UnknownReason::ConflictingEvidence);
}
