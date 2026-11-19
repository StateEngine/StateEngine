//! Recipient-scoped durable notice planning. No callback or read lease crosses a commit wait.
mod coalesce;
mod observation;
mod restart;
mod settlement;
use crate::{
    commit::{Cx, OpStep},
    dispatch::Kernel,
    scope,
    store_error::store_error,
};
pub use coalesce::reserve_coalesced;
pub use observation::{
    InputAccepted, MailReceipt, ObservationThen, ObserveOffer, confirm_delivery,
    observation_committed, observe_offer,
};
pub use restart::{RestartNotice, finish_retirement, retire_uncertain};
use se_store::{
    Actor, CommitReceipt, EffectIntent, EffectKind, EventBody, ProjectionRecord, ReadBudget,
    RecordId, RecordIdentity, Revision, WriterModeValue,
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
    pub more_pending: bool,
}
pub struct MailThen {
    key: IdempotencyKey,
    target: MailTarget,
    more_pending: bool,
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
        more_pending: false,
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
                    more_pending: false,
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
    coalesce::reserve_coalesced_bounded(kernel, cx, request, false, Vec::new(), maximum_ids)
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
    let mut requested = None;
    for id in &receipt.events {
        let event = scope::require_present(
            cx.read.event(id.clone()).map_err(|e| store_error(&e))?,
            "mail reservation event",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if event.writer.kind() != receipt.writer.kind() || event.durability != receipt.durability {
            return Err(scope::unreadable(
                "mail reservation completion",
                "event writer or durability differs from the receipt",
            ));
        }
        if matches!(&event.body, EventBody::EffectRequested { request_key, intent: EffectIntent::MailNotice(_), .. } if request_key == &then.key)
            && requested.replace(event).is_some()
        {
            return Err(scope::unreadable(
                "mail reservation completion",
                "multiple matching notice requests",
            ));
        }
    }
    let event = requested.ok_or_else(|| {
        scope::unreadable(
            "mail reservation completion",
            "request key resolved to a different operation",
        )
    })?;
    let EventBody::EffectRequested {
        effect,
        intent: EffectIntent::MailNotice(notice),
        ..
    } = &event.body
    else {
        return Err(scope::unreadable(
            "mail reservation completion",
            "matching notice changed",
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
    let mut reservation = readback(cx, &then.target, record)?;
    reservation.more_pending = then.more_pending;
    Ok(reservation)
}
