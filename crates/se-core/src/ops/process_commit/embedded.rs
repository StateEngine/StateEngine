//! Embedded bindings have no owned native lifecycle or machine credentials.
use super::*;
use se_store::{ProjectionRecord, SessionSurface};
use se_types::{AgentId, SessionId};

/// Exact original preparation distinguishes an external service binding from
/// a managed headless client. Provider alone never authorizes this shortcut.
pub fn embedded_session(record: &ProjectionRecord) -> Option<(&SessionId, &str)> {
    let original = &record.original.as_deref().unwrap_or(&record.current).body;
    let EventBody::SessionPrepared {
        session,
        provider: se_store::Provider::SeCode,
        surface: Some(SessionSurface::SeCode),
        native_ref,
        ..
    } = original
    else {
        return None;
    };
    match &record.current.body {
        EventBody::SessionPrepared { .. }
        | EventBody::SessionRevoked { .. }
        | EventBody::SessionEnded { .. } => Some((session, native_ref)),
        EventBody::SessionActivated {
            process: None,
            containment: se_store::ContainmentFact::NotLaunched,
            ..
        } => Some((session, native_ref)),
        _ => None,
    }
}

/// Retire only the selected engine binding. No service execution or final
/// capture observation is invented, and no native process is signalled.
pub fn retire_embedded<R: Snapshot>(
    kernel: &Kernel,
    agent: AgentId,
    selected: ProjectionRecord,
    key: IdempotencyKey,
    reason: String,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let (session, _) = embedded_session(&selected).ok_or_else(|| {
        se_types::SeError::invalid(
            "embedded retirement",
            "an exact process-free external service binding",
        )
    })?;
    let session = session.clone();
    let control = scope::require_present(
        cx.read
            .control_target(agent)
            .map_err(|e| crate::store_error::store_error(&e))?,
        "embedded stop control",
        "Use a currently admitted agent or owner terminal.",
    )?;
    let current = control
        .sessions
        .into_iter()
        .find(|record| embedded_session(record).is_some_and(|(id, _)| id == &session))
        .ok_or_else(|| {
            se_types::SeError::invalid(
                "embedded retirement",
                "the original active binding; reread before retrying",
            )
        })?;
    if current.revision != selected.revision {
        return Err(se_types::SeError::invalid(
            "embedded retirement",
            "the original binding revision; reread before retrying",
        ));
    }
    batch(
        kernel,
        "agent.stop",
        key,
        serde_json::json!({"session": session, "phase":"embedded-binding-retired"}),
        vec![EventBody::SessionRevoked {
            session,
            expected: Expected::Revision(selected.revision),
            reason: InputText::Inline(reason),
        }],
        cx,
    )
}
