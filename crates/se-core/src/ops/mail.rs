//! Recipient-scoped durable notice planning. No callback or read lease crosses a commit wait.
mod observation;
mod settlement;
use crate::{
    commit::{Cx, OpStep},
    dispatch::Kernel,
    scope,
    store_error::store_error,
};
pub use observation::{
    InputAccepted, MailReceipt, ObservationThen, ObserveOffer, confirm_delivery,
    observation_committed, observe_offer,
};
use se_store::{
    Actor, CommitReceipt, EffectIntent, EffectKind, EventBody, ProjectionRecord, ReadBudget,
    RecordId, RecordIdentity, Revision,
    mail::{MailNotice, MailSnapshot, MailThrough},
};
use se_types::{
    AgentId, Cursor, EventId, HostEpoch, IdempotencyKey, MessageId, NoticeId, PageRequest,
    ProjectId, Read, Result, SeError, SessionId, Sha256,
};
pub use settlement::{
    SettleResolved, Settlement, SettlementThen, settle_resolved, settlement_committed,
};
use std::{num::NonZeroU32, time::Duration};

/// Host-verified target facts, not an operation input or an authority credential.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct MailTarget {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
    pub epoch: HostEpoch,
    pub generation: u64,
    pub fingerprint: [u8; 32],
}
pub struct ReserveNotice {
    pub target: MailTarget,
    pub key: IdempotencyKey,
    pub notice_id: RecordId,
    pub effect_id: RecordId,
}
/// Constructed only from a committed immutable intent under recipient readback.
#[derive(Clone, Debug)]
pub struct Reservation {
    pub notice_id: NoticeId,
    pub effect_id: RecordId,
    pub target: MailTarget,
    pub ids: Vec<MessageId>,
    pub through: Cursor,
    pub digest: Sha256,
    pub revision: Revision,
    pub event_id: EventId,
}
pub struct MailThen {
    key: IdempotencyKey,
    target: MailTarget,
}

fn budget(limit: u32, bytes: u32) -> Result<ReadBudget> {
    Ok(ReadBudget {
        page: PageRequest {
            after: None,
            limit: NonZeroU32::new(limit)
                .ok_or_else(|| SeError::invalid("mail limit", "positive"))?,
            max_bytes: NonZeroU32::new(bytes)
                .ok_or_else(|| SeError::invalid("mail bytes", "positive"))?,
        },
        deadline: Duration::from_secs(1),
    })
}
fn authorize<S: MailSnapshot>(cx: &Cx<'_, S>, target: &MailTarget) -> Result<()> {
    if scope::project(cx.admission)? != target.project
        || cx.admission.actor != Actor::Agent(target.agent.clone())
        || cx.admission.session.as_ref() != Some(&target.session)
        || cx.admission.generation != target.generation
    {
        return Err(SeError::invalid(
            "mail reservation authority",
            "the host-verified current recipient session, project and generation; no sender or owner cursor fallback",
        ));
    }
    Ok(())
}
fn matches_target(notice: &MailNotice, target: &MailTarget) -> bool {
    notice.target_agent == target.agent
        && notice.session == target.session
        && notice.epoch == target.epoch
        && notice.generation == target.generation
        && notice.fingerprint == target.fingerprint
}
fn intent(record: &ProjectionRecord) -> Result<(RecordId, &MailNotice)> {
    let original = record.original.as_deref().unwrap_or(&record.current);
    match &original.body {
        EventBody::EffectRequested {
            effect,
            kind: EffectKind::Bell,
            intent: EffectIntent::MailNotice(notice),
            principal: Some(Actor::Agent(agent)),
            ..
        } if agent == &notice.target_agent => Ok((*effect, notice)),
        _ => Err(scope::unreadable(
            "mail reservation",
            "indexed debt is not its original Bell notice intent",
        )),
    }
}
fn readback<S: MailSnapshot>(
    cx: &mut Cx<'_, S>,
    target: &MailTarget,
    record: ProjectionRecord,
) -> Result<Reservation> {
    authorize(cx, target)?;
    let (effect, notice) = intent(&record)?;
    notice.validate().map_err(|error| store_error(&error))?;
    if !matches_target(notice, target) {
        return Err(SeError::invalid(
            "mail target",
            "the original reservation's exact session, epoch, generation and fingerprint",
        ));
    }
    Ok(Reservation {
        notice_id: NoticeId::new(format!(
            "notice-{}",
            se_types::hex_lower(notice.notice_id.as_bytes())
        ))?,
        effect_id: effect,
        target: target.clone(),
        ids: notice.ids.clone(),
        through: cx
            .read
            .mail_cursor(&notice.through)
            .map_err(|error| store_error(&error))?,
        digest: Sha256::from_bytes(notice.digest),
        revision: record.revision,
        event_id: record
            .original
            .as_deref()
            .unwrap_or(&record.current)
            .header
            .event
            .clone(),
    })
}
/// Select the oldest unresolved recipient messages. A mailbox with no work has
/// a measured Absent result, never an invalid zero-ID notification.
pub fn reserve_notice<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    request: ReserveNotice,
) -> Result<OpStep<Read<Reservation>, MailThen>> {
    reserve_notice_bounded(kernel, cx, request, 32)
}
/// A native consumer may negotiate a smaller IDs-per-notice ceiling. The
/// committed descriptor remains whole; no adapter truncates it after commit.
pub fn reserve_notice_bounded<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    request: ReserveNotice,
    maximum_ids: u32,
) -> Result<OpStep<Read<Reservation>, MailThen>> {
    if !(1..=32).contains(&maximum_ids) {
        return Err(SeError::invalid("notice IDs", "1..32"));
    }
    authorize(cx, &request.target)?;
    match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), request.key.clone())
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value: receipt } => {
            return committed(
                kernel,
                cx,
                MailThen {
                    key: request.key,
                    target: request.target,
                },
                receipt,
            )
            .map(|value| OpStep::Complete(Read::Present { value }));
        }
        Read::Absent { .. } => (),
        Read::Unknown { what } => {
            return Err(scope::unreadable("mail request reconciliation", &what));
        }
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
    }
    let notices = cx
        .read
        .mail_notices(request.target.agent.clone(), budget(100, 262144)?)
        .map_err(|error| store_error(&error))?;
    for record in notices.items() {
        let (_, notice) = intent(record)?;
        let mut pending = false;
        for id in &notice.ids {
            let message = scope::require_present(
                cx.read
                    .message(id.clone())
                    .map_err(|error| store_error(&error))?,
                "reserved mail",
                scope::COMMITTED_READ_RECOVERY,
            )?;
            pending |= message.delivered.is_none()
                && message.read.is_none()
                && message.dismissed.is_none()
                && message.superseded_by.is_none();
        }
        if matches_target(notice, &request.target) && pending {
            return readback(cx, &request.target, record.clone())
                .map(|value| OpStep::Complete(Read::Present { value }));
        }
    }
    if !notices.window().complete() {
        return Err(scope::unreadable(
            "mail reservation debt",
            "unresolved notice inventory is incomplete; preserve original notice identities and continue its cursor",
        ));
    }
    let messages = cx
        .read
        .mail_pending(request.target.agent.clone(), budget(maximum_ids, 262144)?)
        .map_err(|error| store_error(&error))?;
    let window = messages
        .window()
        .fields()
        .ok_or_else(|| scope::unreadable("mail debt", "query has no measured store window"))?;
    if messages.items().is_empty() {
        if !messages.window().complete() {
            return Err(scope::unreadable(
                "mail debt",
                "empty incomplete page is not an empty mailbox",
            ));
        }
        return Ok(OpStep::Complete(Read::Absent {
            checked: "Complete indexed recipient inbox contains no unresolved messages".into(),
        }));
    }
    let info = cx.read.info();
    let mut notice = MailNotice {
        version: 1,
        notice_id: request.notice_id,
        target_agent: request.target.agent.clone(),
        session: request.target.session.clone(),
        epoch: request.target.epoch.clone(),
        generation: request.target.generation,
        fingerprint: request.target.fingerprint,
        ids: messages
            .items()
            .iter()
            .map(|message| message.message.clone())
            .collect(),
        through: MailThrough {
            store: info.id,
            incarnation: info.incarnation,
            sequence: window.to.get(),
        },
        digest: [0; 32],
    };
    loop {
        notice.digest = notice
            .expected_digest()
            .map_err(|error| store_error(&error))?;
        let size = serde_json::to_vec(&notice)
            .map_err(|error| scope::unreadable("mail notice encoding", &error.to_string()))?
            .len();
        if size <= 8192 {
            break;
        }
        if notice.ids.len() == 1 {
            return Err(SeError::too_large("complete mail notice", 8192, size));
        }
        notice.ids.pop();
    }
    notice.validate().map_err(|error| store_error(&error))?;
    let cause = messages.items()[0].event.clone();
    let event = kernel.event(
        EventBody::EffectRequested {
            principal: Some(Actor::Agent(request.target.agent.clone())),
            effect: request.effect_id,
            kind: EffectKind::Bell,
            intent: EffectIntent::MailNotice(Box::new(notice)),
            cause,
            request_key: request.key.clone(),
        },
        cx,
    )?;
    let batch = kernel.batch(
        "mail.reserve_notice",
        request.key.clone(),
        serde_json::json!({"target":request.target}),
        event,
        cx,
    )?;
    Ok(OpStep::Commit {
        batch,
        then: MailThen {
            key: request.key,
            target: request.target,
        },
    })
}
/// The host reopens an admitted recipient snapshot after the actual writer
/// completes. This function cannot turn an unconfirmed draft into a notice.
pub fn committed<S: MailSnapshot>(
    _kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    then: MailThen,
    receipt: CommitReceipt,
) -> Result<Reservation> {
    authorize(cx, &then.target)?;
    super::receipt::receipt_key(&receipt, &then.key, "mail reservation completion")?;
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    let EventBody::EffectRequested {
        effect,
        intent: EffectIntent::MailNotice(notice),
        ..
    } = &event.body
    else {
        return Err(scope::unreadable(
            "mail reservation completion",
            "request key resolved to a different operation",
        ));
    };
    if !matches_target(notice, &then.target) {
        return Err(SeError::invalid(
            "mail reservation retry",
            "the original target bound to this request key",
        ));
    }
    let record = scope::require_present(
        cx.read
            .effect(*effect)
            .map_err(|error| store_error(&error))?,
        "committed mail reservation",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    // A stable request receipt remains history after settlement. Replaying it
    // must not promote its old, resolved descriptor into live delivery work.
    if matches!(record.current.body, EventBody::EffectSettled { .. }) {
        return Err(SeError::new(se_types::Detail::StateConflict(
            se_types::details::StateConflict {
                subject: "mail reservation retry".into(),
                reason: "this request's original reservation is already settled".into(),
                next_step: "Use a fresh reservation request and fresh notice/effect identities for remaining unread mail; preserve the settled receipt as history".into(),
            },
        )));
    }
    readback(cx, &then.target, record)
}
