//! Fold unread mail into one durable notice at a provider's quiet boundary.
use super::*;
use se_store::{EffectOutcome, Expected, MessageRecord};

pub fn reserve_coalesced<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    request: ReserveNotice,
    reoffer: bool,
    excluded: Vec<MessageId>,
) -> Result<OpStep<Read<Reservation>, MailThen>> {
    reserve_coalesced_bounded(kernel, cx, request, reoffer, excluded, 32)
}

pub(super) fn reserve_coalesced_bounded<S: MailSnapshot>(
    kernel: &Kernel,
    cx: &mut Cx<'_, S>,
    request: ReserveNotice,
    reoffer: bool,
    excluded: Vec<MessageId>,
    maximum_ids: u32,
) -> Result<OpStep<Read<Reservation>, MailThen>> {
    authorize(cx, &request.target)?;
    match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), request.key.clone())
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => {
            let target = request.target.clone();
            let mut reservation = committed(
                kernel,
                cx,
                MailThen {
                    key: request.key,
                    target: request.target,
                    more_pending: false,
                },
                value,
            )?;
            let mut seen = excluded;
            seen.extend(reservation.ids.iter().cloned());
            reservation.more_pending = !select_unread(cx, &target, &seen, reoffer, maximum_ids)?
                .0
                .is_empty();
            return Ok(OpStep::Complete(Read::Present { value: reservation }));
        }
        Read::Absent { .. } => {}
        Read::Unknown { what } => {
            return Err(scope::unreadable("mail reservation reconciliation", &what));
        }
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
    }
    if !reoffer && excluded.is_empty() {
        let pending = cx
            .read
            .mail_pending(request.target.agent.clone(), budget(1, 262144)?)
            .map_err(|e| store_error(&e))?;
        if pending.items().is_empty() {
            if !pending.window().complete() {
                return Err(scope::unreadable(
                    "mail debt",
                    "the pending inbox page is incomplete",
                ));
            }
            return Ok(OpStep::Complete(Read::Absent {
                checked: "No non-quiet undelivered mail is waiting".into(),
            }));
        }
    }
    let (selected, through, eligible) =
        select_unread(cx, &request.target, &excluded, reoffer, maximum_ids)?;
    if selected.is_empty() {
        return Ok(OpStep::Complete(Read::Absent {
            checked: "No unread mail is waiting".into(),
        }));
    }
    let (mut bodies, requested, more_pending) =
        build_notice(cx, &request, &selected, through, eligible)?;
    bodies.push(requested);
    let batch = super::super::process_commit::batch(
        kernel,
        "mail.reserve_coalesced",
        request.key.clone(),
        serde_json::json!({"target":request.target,"reoffer":reoffer,"excluded":excluded}),
        bodies,
        cx,
    )?;
    Ok(OpStep::Commit {
        batch,
        then: MailThen {
            key: request.key,
            target: request.target,
            more_pending,
        },
    })
}

fn select_unread<S: MailSnapshot>(
    cx: &mut Cx<'_, S>,
    target: &MailTarget,
    excluded: &[MessageId],
    reoffer: bool,
    maximum_ids: u32,
) -> Result<(Vec<MessageRecord>, Option<u64>, usize)> {
    let excluded_set: std::collections::HashSet<&MessageId> = excluded.iter().collect();
    let mut groups: [Vec<MessageRecord>; 4] = std::array::from_fn(|_| Vec::new());
    let mut after = None;
    let mut eligible = 0_usize;
    let mut through = None;
    let started = std::time::Instant::now();
    for _ in 0..1000 {
        if started.elapsed() >= Duration::from_secs(1) {
            return Err(scope::unreadable(
                "mail inbox",
                "unread inventory exceeded its one-second scan bound",
            ));
        }
        let mut page_budget = budget(100, 262144)?;
        page_budget.page.after = after;
        let page = cx
            .read
            .mail_unread(target.agent.clone(), page_budget)
            .map_err(|e| store_error(&e))?;
        let window = page
            .window()
            .fields()
            .ok_or_else(|| scope::unreadable("mail inbox", "snapshot boundary is unavailable"))?;
        through.get_or_insert(window.to.get());
        for item in page.items() {
            if item.superseded_by.is_some()
                || (!reoffer && item.delivered.is_some())
                || excluded_set.contains(&item.message)
            {
                continue;
            }
            eligible += 1;
            let group = usize::from(item.quiet) * 2 + usize::from(item.delivered.is_some());
            if groups[group].len() < 32 {
                groups[group].push(item.clone());
            }
        }
        if let Some(next) = page.next() {
            after = Some(next.clone());
        } else {
            if !page.window().complete() {
                return Err(scope::unreadable(
                    "mail inbox",
                    "unread inventory is incomplete",
                ));
            }
            after = None;
            break;
        }
    }
    if after.is_some() {
        return Err(scope::unreadable(
            "mail inbox",
            "unread inventory exceeded its bounded scan",
        ));
    }
    let selected: Vec<MessageRecord> = groups
        .into_iter()
        .flatten()
        .take(maximum_ids as usize)
        .collect();
    Ok((selected, through, eligible))
}

fn build_notice<S: MailSnapshot>(
    cx: &mut Cx<'_, S>,
    request: &ReserveNotice,
    selected: &[MessageRecord],
    through: Option<u64>,
    eligible: usize,
) -> Result<(
    Vec<EventBody<se_store::InputText>>,
    EventBody<se_store::InputText>,
    bool,
)> {
    let notices = cx
        .read
        .mail_notices(request.target.agent.clone(), budget(100, 262144)?)
        .map_err(|e| store_error(&e))?;
    if !notices.window().complete() {
        return Err(scope::unreadable(
            "mail reservation debt",
            "unresolved notice inventory is incomplete",
        ));
    }
    let mut more_pending = eligible > selected.len();
    let ids: Vec<MessageId> = selected.iter().map(|m| m.message.clone()).collect();
    let info = cx.read.info();
    let mut notice = MailNotice {
        version: 1,
        notice_id: request.notice_id,
        target_agent: request.target.agent.clone(),
        session: request.target.session.clone(),
        epoch: request.target.epoch.clone(),
        generation: request.target.generation,
        fingerprint: request.target.fingerprint,
        ids: ids.clone(),
        through: MailThrough {
            store: info.id.clone(),
            incarnation: info.incarnation,
            sequence: through
                .ok_or_else(|| scope::unreadable("mail inbox", "missing snapshot boundary"))?,
        },
        digest: [0; 32],
    };
    loop {
        notice.digest = notice.expected_digest().map_err(|e| store_error(&e))?;
        let bytes = serde_json::to_vec(&notice)
            .map_err(|e| scope::unreadable("mail notice encoding", &e.to_string()))?
            .len();
        if bytes <= 8192 {
            break;
        }
        if notice.ids.len() == 1 {
            return Err(SeError::too_large("complete mail notice", 8192, bytes));
        }
        notice.ids.pop();
        more_pending = true;
    }
    let ids = notice.ids.clone();
    notice.validate().map_err(|e| store_error(&e))?;
    let requested = EventBody::EffectRequested {
        principal: Some(Actor::Agent(request.target.agent.clone())),
        effect: request.effect_id,
        kind: EffectKind::Bell,
        intent: EffectIntent::MailNotice(Box::new(notice)),
        cause: selected[0].event.clone(),
        request_key: request.key.clone(),
    };
    let mut bodies = Vec::new();
    for record in notices.items() {
        let (effect, old) = intent(record)?;
        let mut unresolved = Vec::new();
        for id in &old.ids {
            let message = scope::require_present(
                cx.read.message(id.clone()).map_err(|e| store_error(&e))?,
                "reserved mail",
                scope::COMMITTED_READ_RECOVERY,
            )?;
            if message.read.is_none()
                && message.dismissed.is_none()
                && message.superseded_by.is_none()
            {
                unresolved.push(id);
            }
        }
        if unresolved.is_empty() || unresolved.iter().all(|id| ids.contains(id)) {
            let attempts = u32::try_from(record.revision.value.get().saturating_sub(1))
                .map_err(|_| SeError::invalid("mail attempts", "bounded revision"))?;
            let reason = if unresolved.is_empty() {
                "all reserved messages already resolved".to_owned()
            } else {
                format!(
                    "folded into notice {}",
                    se_types::hex_lower(request.notice_id.as_bytes())
                )
            };
            bodies.push(EventBody::EffectSettled {
                effect,
                expected: Expected::Revision(record.revision),
                outcome: EffectOutcome::Abandoned,
                evidence: vec![],
                failure: Some(reason),
                attempts,
            });
        }
    }
    Ok((bodies, requested, more_pending))
}
