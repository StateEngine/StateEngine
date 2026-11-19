//! Retire an uncertain offer without claiming delivery or recipient read.
use super::*;
use se_store::{EffectOutcome, Expected};

pub struct RestartNotice {
    pub target: MailTarget,
    pub effect: RecordId,
}

pub fn retire_uncertain<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    request: RestartNotice,
) -> Result<OpStep<(), IdempotencyKey>> {
    authorize(cx, &request.target)?;
    let record = scope::require_present(
        cx.read
            .effect(request.effect)
            .map_err(|error| store_error(&error))?,
        "restart notice",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let (_, notice) = intent(&record)?;
    if notice.target_agent != request.target.agent || notice.session != request.target.session {
        return Err(SeError::invalid(
            "restart notice",
            "the original session and notice target",
        ));
    }
    let key = IdempotencyKey::new(format!(
        "mail.restart.{}",
        se_types::hex_lower(request.effect.as_bytes())
    ))?;
    match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => {
            finish_retirement(cx, key, value)?;
            return Ok(OpStep::Complete(()));
        }
        Read::Absent { .. } => (),
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("restart notice receipt", &what)),
    }
    if matches!(record.current.body, EventBody::EffectSettled { .. }) {
        return Ok(OpStep::Complete(()));
    }
    let attempts = u32::try_from(record.revision.value.get().saturating_sub(1))
        .map_err(|_| SeError::invalid("restart notice", "a bounded offer count"))?;
    let event = kernel.event(
        EventBody::EffectSettled {
            effect: request.effect,
            expected: Expected::Revision(record.revision),
            outcome: EffectOutcome::Abandoned,
            evidence: Vec::new(),
            failure: Some("service restarted; original offer outcome remains unknown".into()),
            attempts,
        },
        cx,
    )?;
    let batch = kernel.batch(
        "mail.restart",
        key.clone(),
        serde_json::json!({"effect":request.effect}),
        event,
        cx,
    )?;
    Ok(OpStep::Commit { batch, then: key })
}

pub fn finish_retirement<S: MailSnapshot>(
    cx: &mut Cx<'_, S>,
    key: IdempotencyKey,
    receipt: se_store::CommitReceipt,
) -> Result<()> {
    super::super::receipt::receipt_key(&receipt, &key, "restart notice completion")?;
    let event = super::super::receipt::committed_event(cx.read, &receipt)?;
    if !matches!(
        event.body,
        EventBody::EffectSettled {
            outcome: EffectOutcome::Abandoned,
            ..
        }
    ) {
        return Err(scope::unreadable(
            "restart notice",
            "the retained receipt is not an uncertain retirement",
        ));
    }
    Ok(())
}
