//! Retain a failed capture without advancing or replacing its source cursor.
use super::*;
use crate::store_error::store_error;
use se_store::{Actor, Consent};
use se_types::{ErrorBody, SessionId};

pub fn capture_failure<R: Snapshot>(
    kernel: &Kernel,
    session: SessionId,
    failure: ErrorBody,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let source = session_credential_id(&session, "capture-source")?;
    let record = scope::require_present(
        cx.read
            .capture_source(source)
            .map_err(|e| store_error(&e))?,
        "failed capture source",
        "Restore the original capture source; preserve its committed cursor.",
    )?;
    let original = record.original.as_deref().unwrap_or(&record.current);
    if cx.admission.session.as_ref() != Some(&session)
        || !matches!(&cx.admission.actor, Actor::Agent(_))
        || !matches!(&original.body, EventBody::CaptureSource { session: found, consent: Consent::Capture, .. } if found == &session)
    {
        return Err(scope::unreadable(
            "failed capture",
            "the original admitted session and capture consent are required",
        ));
    }
    let offset = match record.current.body {
        EventBody::CaptureSource { .. } => 0,
        EventBody::CaptureProgress { new_offset, .. } => new_offset,
        _ => {
            return Err(scope::unreadable(
                "failed capture",
                "the committed source cursor is unavailable",
            ));
        }
    };
    let mut cause = failure.message();
    if cause.len() > 16000 {
        let mut end = 16000;
        while !cause.is_char_boundary(end) {
            end -= 1;
        }
        cause.truncate(end);
        cause.push_str(" [diagnostic truncated]");
    }
    let intent = serde_json::json!({"source":source,"session":session,"cursor":record.current.header.event,"offset":offset,"code":failure.code(),"cause":cause,"retry":failure.retry()});
    let digest = Sha256::digest(
        serde_json::to_vec(&intent)
            .map_err(|e| scope::unreadable("failed capture identity", &e.to_string()))?,
    );
    let phase = format!("capture-failure-{digest:x}");
    batch(
        kernel,
        "agent.launch",
        phase_key(&session.as_str().parse()?, &phase)?,
        intent,
        vec![EventBody::CaptureFailed {
            source,
            session,
            from_offset: offset,
            to_offset: offset,
            code: failure.code(),
            cause,
            retry: failure.retry().clone(),
        }],
        cx,
    )
}
