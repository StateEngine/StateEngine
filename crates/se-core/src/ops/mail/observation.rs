//! Host observations remain separate from transport, delivery and recipient read.
use super::*;
use se_store::{
    Role, StoredText,
    mail::{OfferEvidence, OfferObservation},
};
use sha2::{Digest, Sha256 as Hasher};

pub struct ObserveOffer {
    pub target: MailTarget,
    pub effect: RecordId,
    pub attempt: RecordId,
    pub evidence: OfferObservation,
}
/// The host supplies correlation to an actual committed user-input capture, not
/// queue admission. The full accepted input hash binds its provider observation
/// to the immutable captured bytes; this internal port is not a model tool.
pub struct InputAccepted {
    pub target: MailTarget,
    pub effect: RecordId,
    pub message: MessageId,
    pub evidence: EventId,
    pub accepted_text_sha256: [u8; 32],
    pub key: IdempotencyKey,
}
#[derive(Clone, Debug)]
pub struct MailReceipt {
    pub reservation: Reservation,
    pub event_id: EventId,
}
enum Observation {
    Offer {
        attempt: RecordId,
        evidence: Box<OfferObservation>,
    },
    Delivered {
        message: MessageId,
        evidence: EventId,
    },
}
pub struct ObservationThen {
    key: IdempotencyKey,
    target: MailTarget,
    effect: RecordId,
    observation: Observation,
}
fn reservation<S: MailSnapshot>(
    cx: &mut Cx<'_, S>,
    target: &MailTarget,
    effect: RecordId,
) -> Result<Reservation> {
    authorize(cx, target)?;
    let record = scope::require_present(
        cx.read
            .effect(effect)
            .map_err(|error| store_error(&error))?,
        "original mail reservation",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    readback(cx, target, record)
}
fn replay<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    then: ObservationThen,
) -> Result<std::result::Result<MailReceipt, ObservationThen>> {
    match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), then.key.clone())
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => Ok(Ok(observation_committed(kernel, cx, then, value)?)),
        Read::Absent { .. } => Ok(Err(then)),
        Read::Unknown { what } => Err(scope::unreadable("mail observation reconciliation", &what)),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
    }
}
fn observation_identity(value: &OfferObservation) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| scope::unreadable("mail evidence encoding", &error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| SeError::invalid("mail evidence", "a typed observation object"))?
        .remove("observed_at_us");
    Ok(value)
}
pub fn observe_offer<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    input: ObserveOffer,
) -> Result<OpStep<MailReceipt, ObservationThen>> {
    let original = reservation(cx, &input.target, input.effect)?;
    input
        .evidence
        .validate()
        .map_err(|error| store_error(&error))?;
    let record = scope::require_present(
        cx.read
            .effect(input.effect)
            .map_err(|error| store_error(&error))?,
        "mail intent",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let (_, notice) = intent(&record)?;
    if input.evidence.notice_id != notice.notice_id
        || input.evidence.target_agent != input.target.agent
        || input.evidence.session != input.target.session
        || input.evidence.epoch != input.target.epoch
        || input.evidence.generation != input.target.generation
        || input.evidence.fingerprint != input.target.fingerprint
        || input.evidence.digest != *original.digest.as_bytes()
    {
        return Err(SeError::invalid(
            "mail offer evidence",
            "the exact original committed notice and target",
        ));
    }
    let key = se_store::mail::offer_key(input.effect, input.attempt)
        .map_err(|error| store_error(&error))?;
    let then = ObservationThen {
        key: key.clone(),
        target: input.target,
        effect: input.effect,
        observation: Observation::Offer {
            attempt: input.attempt,
            evidence: Box::new(input.evidence),
        },
    };
    let then = match replay(kernel, cx, then)? {
        Ok(receipt) => return Ok(OpStep::Complete(receipt)),
        Err(then) => then,
    };
    let Observation::Offer { attempt, evidence } = &then.observation else {
        return Err(SeError::invalid("mail observation", "offer"));
    };
    let event = kernel.event(
        EventBody::EffectOffered {
            effect: then.effect,
            principal: Actor::Agent(then.target.agent.clone()),
            attempt: *attempt,
            evidence: OfferEvidence::Observed(evidence.clone()),
        },
        cx,
    )?;
    let batch=kernel.batch("mail.observe_offer",key,serde_json::json!({"target":then.target,"effect":then.effect,"attempt":attempt,"evidence":observation_identity(evidence)?}),event,cx)?;
    Ok(OpStep::Commit { batch, then })
}
pub fn confirm_delivery<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    input: InputAccepted,
) -> Result<OpStep<MailReceipt, ObservationThen>> {
    let original = reservation(cx, &input.target, input.effect)?;
    if !original.ids.contains(&input.message) {
        return Err(SeError::invalid(
            "mail delivery",
            "a message belonging to this original reservation",
        ));
    }
    let captured = scope::require_present(
        cx.read
            .event(input.evidence.clone())
            .map_err(|error| store_error(&error))?,
        "captured accepted mail input",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let matching = match &captured.body {
        EventBody::SessionTurn {
            agent,
            session,
            role: Role::User,
            text: StoredText::Present(text),
            ..
        } => {
            agent == &input.target.agent
                && session == &input.target.session
                && <[u8; 32]>::from(Hasher::digest(text.as_bytes())) == input.accepted_text_sha256
        }
        _ => false,
    };
    let requested = scope::require_present(
        cx.read
            .event(original.event_id.clone())
            .map_err(|error| store_error(&error))?,
        "original mail request",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    if !matching || captured.header.occurred_at_us < requested.header.occurred_at_us {
        return Err(SeError::invalid(
            "mail delivery evidence",
            "the actual correlated user-input capture for this session, after its notice reservation; transport or queue admission is insufficient",
        ));
    }
    let then = ObservationThen {
        key: input.key.clone(),
        target: input.target,
        effect: input.effect,
        observation: Observation::Delivered {
            message: input.message,
            evidence: input.evidence,
        },
    };
    let then = match replay(kernel, cx, then)? {
        Ok(receipt) => return Ok(OpStep::Complete(receipt)),
        Err(then) => then,
    };
    let Observation::Delivered { message, evidence } = &then.observation else {
        return Err(SeError::invalid("mail observation", "delivery"));
    };
    let event = kernel.event(
        EventBody::MessageDelivered {
            message: message.clone(),
            recipient: Actor::Agent(then.target.agent.clone()),
            evidence: evidence.clone(),
        },
        cx,
    )?;
    let batch=kernel.batch("mail.confirm_delivery",input.key,serde_json::json!({"target":then.target,"effect":then.effect,"message":message,"evidence":evidence,"accepted_text_sha256":input.accepted_text_sha256}),event,cx)?;
    Ok(OpStep::Commit { batch, then })
}
/// Reopen a fresh recipient snapshot after the real writer commits. Offered and
/// delivered results leave read/dismiss marks and unresolved Bell debt intact.
pub fn observation_committed<S: MailSnapshot>(
    _kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    then: ObservationThen,
    receipt: CommitReceipt,
) -> Result<MailReceipt> {
    authorize(cx, &then.target)?;
    super::super::receipt::receipt_key(&receipt, &then.key, "mail observation completion")?;
    let event = super::super::receipt::committed_event(cx.read, &receipt)?;
    let matches = match (&then.observation, &event.body) {
        (
            Observation::Offer { attempt, evidence },
            EventBody::EffectOffered {
                effect,
                principal,
                attempt: actual,
                evidence: OfferEvidence::Observed(observed),
            },
        ) => {
            effect == &then.effect
                && principal == &Actor::Agent(then.target.agent.clone())
                && actual == attempt
                && observation_identity(evidence)? == observation_identity(observed)?
        }
        (
            Observation::Delivered { message, evidence },
            EventBody::MessageDelivered {
                message: actual,
                recipient,
                evidence: observed,
            },
        ) => {
            message == actual
                && evidence == observed
                && recipient == &Actor::Agent(then.target.agent.clone())
        }
        _ => false,
    };
    if !matches {
        return Err(SeError::invalid(
            "mail observation retry",
            "the original effect, attempt, target and evidence bound to this key",
        ));
    }
    Ok(MailReceipt {
        reservation: reservation(cx, &then.target, then.effect)?,
        event_id: event.header.event,
    })
}
