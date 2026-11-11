//! Reconcile a notice from committed recipient read or dismiss dispositions.
//! Settlement never invents delivery or recipient read.
use super::*;
use se_store::{EffectOutcome, Expected};
#[derive(Clone, Debug)]
pub struct Settlement {
    pub effect: RecordId,
    pub notice_id: RecordId,
    pub event_id: EventId,
}
pub struct SettlementThen {
    key: IdempotencyKey,
    target: MailTarget,
    effect: RecordId,
    notice_id: RecordId,
}

/// Actual committed disposition IDs obtained by the host's finite store read. No
/// boolean, transport report or provider acknowledgement can replace these.
pub struct SettleResolved {
    pub target: MailTarget,
    pub effect: RecordId,
    pub evidence: Vec<EventId>,
}

/// The host calls this before reusing/selecting a pending notice after real
/// read/dismiss triggers. Transport or capture alone cannot resolve debt.
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn settle_resolved<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    request: SettleResolved,
) -> Result<OpStep<Read<Settlement>, SettlementThen>> {
    let SettleResolved {
        target,
        effect,
        evidence,
    } = request;
    authorize(cx, &target)?;
    let record = scope::require_present(
        cx.read
            .effect(effect)
            .map_err(|error| store_error(&error))?,
        "original mail debt",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let (_, notice) = intent(&record)?;
    if notice.target_agent != target.agent {
        return Err(SeError::invalid(
            "mail settlement",
            "the actual recipient, including for inherited old-session debt",
        ));
    }
    let notice_id = notice.notice_id;
    let key = IdempotencyKey::new(format!(
        "mail.settle.{}",
        se_types::hex_lower(effect.as_bytes())
    ))?;
    let then = SettlementThen {
        key: key.clone(),
        target,
        effect,
        notice_id,
    };
    match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => {
            return settlement_committed(cx, then, value)
                .map(|value| OpStep::Complete(Read::Present { value }));
        }
        Read::Absent { .. } => (),
        Read::Unknown { what } => {
            return Err(scope::unreadable("mail settlement reconciliation", &what));
        }
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
    }
    if evidence.len() > 32 {
        return Err(SeError::invalid(
            "mail resolution evidence",
            "at most 32 original message disposition events",
        ));
    }
    let mut markers = Vec::new();
    for id in evidence {
        let event = scope::require_present(
            cx.read
                .mail_disposition(id, then.target.agent.clone())
                .map_err(|error| store_error(&error))?,
            "committed recipient disposition",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if markers
            .iter()
            .any(|old: &se_store::StoredEvent| old.header.event == event.header.event)
        {
            return Err(SeError::invalid(
                "mail resolution evidence",
                "distinct committed marker identities",
            ));
        }
        match &event.body {
            EventBody::MessageRead { message, recipient }
            | EventBody::MessageDismissed { message, recipient }
                if recipient == &cx.admission.actor && notice.ids.contains(message) => {}
            _ => {
                return Err(SeError::invalid(
                    "mail resolution evidence",
                    "actual recipient read/dismiss events for original notice IDs",
                ));
            }
        }
        markers.push(event);
    }
    for id in &notice.ids {
        let message = scope::require_present(
            cx.read
                .message(id.clone())
                .map_err(|error| store_error(&error))?,
            "reserved message disposition",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if message.recipient != cx.admission.actor {
            return Err(SeError::invalid(
                "mail settlement",
                "all original messages belong to this actual recipient",
            ));
        }
        if message.read.is_none() && message.dismissed.is_none() {
            return Ok(OpStep::Complete(Read::Absent {
                checked:
                    "The original notice still has unresolved recipient messages; preserve its debt"
                        .into(),
            }));
        }
        let verified = markers.iter().any(|event| match &event.body {
            EventBody::MessageRead {
                message: actual, ..
            } => actual == id && message.read.as_ref() == Some(&event.position),
            EventBody::MessageDismissed {
                message: actual, ..
            } => actual == id && message.dismissed.as_ref() == Some(&event.position),
            _ => false,
        });
        if !verified {
            return Err(scope::unreadable(
                "mail resolution evidence",
                "a resolved message has no matching original committed marker; reread recipient dispositions instead of inferring success",
            ));
        }
    }
    // All original IDs were independently verified above. One actual disposition
    // anchors this completion within the legacy bounded settlement receipt;
    // the complete immutable recipient history remains in the same store.
    let evidence = markers
        .first()
        .ok_or_else(|| scope::unreadable("mail settlement", "no actual recipient evidence"))?
        .header
        .event
        .clone();
    if let EventBody::EffectSettled { outcome, .. } = &record.current.body {
        return if *outcome == EffectOutcome::Witnessed {
            Ok(OpStep::Complete(Read::Present {
                value: Settlement {
                    effect,
                    notice_id,
                    event_id: record.current.header.event,
                },
            }))
        } else {
            Ok(OpStep::Complete(Read::Absent{checked:"Original notice has a terminal failure/abandonment; preserve that history without rewriting it".into()}))
        };
    }
    let attempts = u32::try_from(record.revision.value.get().saturating_sub(1)).map_err(|_| {
        SeError::invalid("mail offer attempts", "a bounded original effect revision")
    })?;
    let event = kernel.event(
        EventBody::EffectSettled {
            effect,
            expected: Expected::Revision(record.revision),
            outcome: EffectOutcome::Witnessed,
            evidence: vec![evidence],
            failure: None,
            attempts,
        },
        cx,
    )?;
    let batch = kernel.batch(
        "mail.settle_resolved",
        key,
        serde_json::json!({"effect":effect,"recipient":then.target.agent}),
        event,
        cx,
    )?;
    Ok(OpStep::Commit { batch, then })
}
pub fn settlement_committed<S: MailSnapshot>(
    cx: &mut Cx<'_, S>,
    then: SettlementThen,
    receipt: CommitReceipt,
) -> Result<Settlement> {
    authorize(cx, &then.target)?;
    super::super::receipt::receipt_key(&receipt, &then.key, "mail settlement completion")?;
    let event = super::super::receipt::committed_event(cx.read, &receipt)?;
    if !matches!(&event.body,EventBody::EffectSettled{effect,outcome:EffectOutcome::Witnessed,..} if effect==&then.effect)
    {
        return Err(scope::unreadable(
            "mail settlement completion",
            "receipt is not the original resolved notice",
        ));
    }
    Ok(Settlement {
        effect: then.effect,
        notice_id: then.notice_id,
        event_id: event.header.event,
    })
}
