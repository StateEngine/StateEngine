//! Retain a failed capture without advancing or replacing its source cursor.
use super::*;
use crate::store_error::store_error;
use se_store::{Actor, Consent};
use se_types::{ErrorBody, SessionId};

/// Record the trusted coordinator's EOF observation without inventing another
/// turn or advancing the byte cursor. A retry can then clear an EOF failure.
/// Live observations bind the exact offset and failure that were read back.
pub fn capture_verified<R: Snapshot>(
    kernel: &Kernel,
    session: SessionId,
    owner: &se_types::HumanId,
    observed: Option<(u64, se_types::EventId)>,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let source = session_credential_id(&session, "capture-source")?;
    let record = scope::require_present(
        cx.read
            .capture_source(source)
            .map_err(|e| store_error(&e))?,
        "verified capture source",
        "Restore the original trusted capture cursor.",
    )?;
    let offset = match &record.current.body {
        EventBody::CaptureSource {
            session: found,
            consent: Consent::Capture,
            ..
        } if found == &session => 0,
        EventBody::CaptureProgress { new_offset, .. } => *new_offset,
        _ => {
            return Err(scope::unreadable(
                "verified capture source",
                "the consented source cursor is unavailable",
            ));
        }
    };
    if cx.admission.session.as_ref() != Some(&session)
        || !matches!(&cx.admission.actor, Actor::Agent(_))
    {
        return Err(scope::unreadable(
            "verified capture",
            "the exact original admitted agent session is required",
        ));
    }
    let bound = scope::require_present(
        cx.read
            .session(session.clone())
            .map_err(|e| store_error(&e))?,
        "verified capture session",
        "Restore the original protected session.",
    )?;
    let (admission, door) = super::super::hook::replay::admission(Some(owner), &bound, cx)?;
    let failure = cx
        .read
        .capture_outcome(source, Some(se_store::EventKind::CaptureFailed))
        .map_err(|e| store_error(&e))?;
    let after = match &failure {
        se_types::Read::Present { value } => &value.header.event,
        se_types::Read::Absent { .. } => &record.current.header.event,
        _ => {
            return Err(scope::unreadable(
                "capture verification",
                "the latest capture failure is unavailable",
            ));
        }
    };
    if let Some((expected_offset, expected_failure)) = observed
        && (expected_offset != offset || expected_failure != *after)
    {
        return Err(scope::unreadable(
            "capture verification",
            "the source cursor or retained failure changed after the native EOF observation; retry its current binding",
        ));
    }
    let mut batch = batch(
        kernel,
        "agent.launch",
        phase_key(
            &session.as_str().parse()?,
            &format!("capture-verified-{after}"),
        )?,
        serde_json::json!({"source":source,"session":session,"offset":offset,"after":after}),
        vec![EventBody::CaptureVerified {
            source,
            session,
            offset,
        }],
        cx,
    )?;
    batch.admission = admission;
    for event in &mut batch.events {
        event.header.door = door;
        // Carry the observation across the planning/submission gap so the
        // writer can refuse an acknowledgement superseded by a newer failure.
        event.header.cause = Some(after.clone());
    }
    Ok(batch)
}

pub fn capture_failure<R: Snapshot>(
    kernel: &Kernel,
    session: SessionId,
    failure: ErrorBody,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    failure_batch(kernel, session, failure, None, cx)
}
/// A trusted coordinator may retain a failed final capture after native exit
/// and session retirement, using the same registered-owner import as replay.
pub fn final_capture_failure<R: Snapshot>(
    kernel: &Kernel,
    session: SessionId,
    owner: &se_types::HumanId,
    failure: ErrorBody,
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    failure_batch(kernel, session, failure, Some(owner), cx)
}
fn failure_batch<R: Snapshot>(
    kernel: &Kernel,
    session: SessionId,
    failure: ErrorBody,
    owner: Option<&se_types::HumanId>,
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
    let recovery = match owner {
        Some(owner) => {
            let bound = scope::require_present(
                cx.read
                    .session(session.clone())
                    .map_err(|e| store_error(&e))?,
                "final capture diagnostic",
                "Restore the exact protected session.",
            )?;
            Some(super::super::hook::replay::admission(
                Some(owner),
                &bound,
                cx,
            )?)
        }
        None => None,
    };
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
    // A repeated failure after a verified retry is a new diagnostic. Replaying
    // the pre-verification receipt would hide the new failed final read.
    let verified = cx
        .read
        .capture_outcome(source, Some(se_store::EventKind::CaptureVerified))
        .map_err(|e| store_error(&e))?;
    let verification = match &verified {
        se_types::Read::Present { value } => Some(&value.header.event),
        se_types::Read::Absent { .. } => None,
        _ => {
            return Err(scope::unreadable(
                "capture failure",
                "the latest EOF verification is unavailable",
            ));
        }
    };
    let intent = serde_json::json!({"source":source,"session":session,"cursor":record.current.header.event,"offset":offset,"verification":verification,"code":failure.code(),"cause":cause,"retry":failure.retry()});
    let digest = Sha256::digest(
        serde_json::to_vec(&intent)
            .map_err(|e| scope::unreadable("failed capture identity", &e.to_string()))?,
    );
    let phase = format!("capture-failure-{digest:x}");
    let mut batch = batch(
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
    )?;
    if let Some((admission, door)) = recovery {
        batch.admission = admission;
        for event in &mut batch.events {
            event.header.door = door;
        }
    }
    Ok(batch)
}
