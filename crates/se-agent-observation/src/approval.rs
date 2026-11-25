//! Report Claude's native permission decision, never assistant or tool-output prose alone.
use super::*;
use se_core::ops::PendingFact;
use serde_json::Value;

const TAIL_BYTES: usize = 256 * 1024;

pub(super) fn observe(plan: &AgentObservationPlan, deadline: Instant) -> Option<PendingFact> {
    if !plan.status_attention
        || plan.control_failure.is_some()
        || plan.row.provider != se_types::Provider::Claude
        || plan.row.session.surface.as_deref() != Some("headless")
        || plan.row.conversation.state != "saved"
    {
        return None;
    }
    let Read::Present { value: evidence } = &plan.capture else {
        return None;
    };
    match denied(plan, evidence, deadline) {
        Ok(Some(since)) => Some(PendingFact {
            what: "Claude permissions".into(),
            since,
            detail: format!(
                "{} ({}): Claude Code denied a tool under its own permissions in the last captured headless turn. Review your Claude Code permission or sandbox settings. If approval is needed, stop this agent and reopen its saved conversation in a window to answer the prompt.",
                plan.row.name, plan.row.id,
            ),
        }),
        Ok(None) => None,
        Err(error) => Some(PendingFact {
            what: "Claude permission observation".into(),
            since: None,
            detail: format!(
                "{} ({}): permission state could not be read: {error}",
                plan.row.name, plan.row.id
            ),
        }),
    }
}

fn denied(
    plan: &AgentObservationPlan,
    evidence: &SourceEvidence,
    deadline: Instant,
) -> Result<Option<Option<String>>> {
    bound(deadline)?;
    let path = evidence
        .path
        .as_ref()
        .ok_or_else(|| invalid("the captured Claude source path"))?
        .to_local()?;
    let mut pin = se_proc::NativeSourcePin::open(&path)
        .map_err(|e| invalid(&e.to_string()))?
        .ok_or_else(|| invalid("the captured Claude source is absent"))?;
    if evidence.incarnation.as_slice() != pin.identity() {
        return Err(invalid("the original captured Claude file incarnation"));
    }
    let end = evidence
        .offset
        .checked_add(evidence.length)
        .ok_or_else(|| invalid("a bounded captured Claude offset"))?;
    let start = end.saturating_sub(TAIL_BYTES as u64);
    let bytes = pin
        .read_at(start, (end - start) as usize)
        .map_err(|e| invalid(&e.to_string()))?
        .bytes;
    if bytes.len() as u64 != end - start {
        return Err(invalid("the complete captured Claude observation tail"));
    }
    let mut lines = bytes.split_inclusive(|byte| *byte == b'\n');
    if start != 0 {
        // The finite tail may begin inside a native record. Never parse that fragment.
        lines.next();
    }
    let mut refusal = None;
    for line in lines {
        bound(deadline)?;
        if !line.ends_with(b"\n") {
            return Err(invalid("newline-terminated captured Claude records"));
        }
        let row: Value = serde_json::from_slice(line)
            .map_err(|e| invalid(&format!("readable captured Claude record: {e}")))?;
        if row.get("sessionId").and_then(Value::as_str) != plan.row.conversation.id.as_deref()
            || row.get("isSidechain").and_then(Value::as_bool) == Some(true)
            || row.get("type").and_then(Value::as_str) != Some("user")
        {
            continue;
        }
        let content = row.pointer("/message/content");
        let blocks = content.and_then(Value::as_array);
        if content.is_some_and(Value::is_string)
            || blocks.is_some_and(|blocks| {
                blocks
                    .iter()
                    .any(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            })
        {
            // A new native input starts another turn; an older denial is not current.
            refusal = None;
        }
        if row
            .pointer("/permissionDecision/decision")
            .and_then(Value::as_str)
            != Some("reject")
            || row.get("toolDenialKind").and_then(Value::as_str).is_none()
        {
            continue;
        }
        if blocks.is_some_and(|blocks| {
            blocks.iter().any(|block| {
                block.get("type").and_then(Value::as_str) == Some("tool_result")
                    && block.get("is_error").and_then(Value::as_bool) == Some(true)
            })
        }) {
            refusal = Some(
                row.get("timestamp")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            );
        }
    }
    pin.validate_path(&path)
        .map_err(|e| invalid(&e.to_string()))?;
    bound(deadline)?;
    Ok(refusal)
}
