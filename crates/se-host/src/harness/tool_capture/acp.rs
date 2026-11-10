//! ACP reports tool-call IDs and status, without proving filesystem authorship.
use super::*;
use serde_json::Value;
pub(crate) fn facts(update: &Value, request: u64, cwd: &str) -> Result<Vec<Fact>> {
    let id = update
        .get("toolCallId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 512)
        .ok_or_else(|| SeError::invalid("ACP tool capture", "the original tool-call identity"))?;
    let mut phases = Vec::new();
    if update.get("sessionUpdate").and_then(Value::as_str) == Some("tool_call") {
        phases.push((Phase::Called, Outcome::Unknown(UnknownReason::Pending)));
    }
    match update.get("status").and_then(Value::as_str) {
        Some("completed") => phases.push((Phase::Completed, Outcome::Succeeded)),
        Some("failed") => phases.push((Phase::Completed, Outcome::Failed)),
        None | Some("pending" | "in_progress") => (),
        _ => {
            return Err(SeError::invalid(
                "ACP tool capture",
                "an explicit supported native status",
            ));
        }
    }
    let target = match update.get("locations") {
        None => Target::Unknown(UnknownReason::NoNativeTarget),
        Some(value) => match value.as_array() {
            None => Target::Unknown(UnknownReason::UnsupportedShape),
            Some(locations) if locations.len() > 16 => Target::Unknown(UnknownReason::OverBudget),
            Some(locations) if locations.is_empty() => {
                Target::Unknown(UnknownReason::NoNativeTarget)
            }
            Some(locations) => {
                let mut paths = Vec::new();
                let mut failure = None;
                for location in locations {
                    let Some(path) = location.get("path").and_then(Value::as_str) else {
                        failure = Some(UnknownReason::UnsupportedShape);
                        break;
                    };
                    if path.len() > 1024 || cwd.len() > 1024 {
                        failure = Some(UnknownReason::OverBudget);
                        break;
                    }
                    if path.is_empty() || path.chars().any(char::is_control) {
                        failure = Some(UnknownReason::UnsupportedShape);
                        break;
                    }
                    paths.push(ObservedPath {
                        spelling: path.into(),
                        cwd: Some(cwd.into()),
                        content_revision: None,
                    });
                }
                match failure {
                    Some(reason) => Target::Unknown(reason),
                    None => Target::Paths(paths),
                }
            }
        },
    };
    Ok(phases
        .into_iter()
        .map(|(phase, outcome)| Fact {
            key: format!("acp/{request}/{id}/{phase:?}"),
            native: NativeIdentity::AcpCall {
                request,
                tool_call_id: id.into(),
            },
            phase,
            // ACP's title and broad tool kind are not a native function name.
            tool: ToolName::Unknown(UnknownReason::UnsupportedShape),
            target: target.clone(),
            outcome,
        })
        .collect())
}
