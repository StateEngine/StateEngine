//! Read actual capture/disposition facts; a written pipe is never delivery.
use super::*;
use se_store::{PositionPurpose, Role, StoredText};

impl LaunchCoordinator {
    pub(super) async fn reconcile_mail(
        &self,
        work: &mut owned::Work,
        target: &core::MailTarget,
        deadline: &Deadline,
    ) -> Result<()> {
        if let Some(flight) = work.mail.flight.as_mut() {
            let evidence = flight.evidence.clone().ok_or_else(|| {
                scope::unreadable("mail transport outcome", "the retained write attempt is unproved; preserve pending mail and stop/relaunch the binding before another offer")
            })?;
            if !flight.observed {
                let request = core::ObserveOffer {
                    target: target.clone(),
                    effect: flight.reservation.effect_id,
                    attempt: flight.attempt,
                    evidence,
                };
                commit::step(
                    &self.store,
                    admission(target),
                    deadline,
                    move |kernel, cx| core::observe_offer(kernel, cx, request),
                    core::observation_committed,
                )
                .await?;
                flight.observed = true;
            }
        }
        // Preserve the attempted offer before an authenticated read can fail.
        // A lost response must leave durable unknown delivery, never no offer.
        if work.secode.is_some() && work.mail.flight.is_some() {
            self.reconcile_secode_notice(work, deadline).await?;
        }
        self.reconcile_captured_mail(work, target, deadline).await
    }

    /// Captured canonical input can settle delivery even after cancellation.
    /// This reads committed capture only and never offers provider input.
    pub(super) async fn reconcile_captured_mail(
        &self,
        work: &mut owned::Work,
        target: &core::MailTarget,
        deadline: &Deadline,
    ) -> Result<()> {
        let previous = work
            .mail
            .flight
            .as_ref()
            .map(|flight| flight.reservation.notice_id.clone());
        if let Some(flight) = work.mail.flight.as_mut() {
            // Only a witnessed zero-byte failure permits a fresh attempt on a
            // later commit/retry wake. Uncertain acceptance retains this flight.
            if flight
                .evidence
                .as_ref()
                .is_some_and(|e| matches!(e.report, se_store::mail::OfferReport::Failed { .. }))
            {
                work.mail.flight = None;
                self.settle_mail(target, deadline).await?;
                return Ok(());
            }
            let recipient = target.agent.clone();
            let session = target.session.clone();
            let through = flight.reservation.through.clone();
            let expected = flight.text_sha256;
            let captured = self
                .store
                .read(admission(target), deadline, move |cx| {
                    let position = cx
                        .read
                        .cursor_position(&through, PositionPurpose::Checked)
                        .map_err(|e| store_error(&e))?;
                    match cx
                        .read
                        .mail_input(
                            recipient,
                            session,
                            position,
                            expected,
                            Duration::from_secs(1),
                        )
                        .map_err(|e| store_error(&e))?
                    {
                        Read::Present { value } => match &value.body {
                            EventBody::SessionTurn {
                                role: Role::User,
                                text: StoredText::Present(text),
                                ..
                            } if <[u8; 32]>::from(Sha256::digest(text.as_bytes())) == expected => {
                                Ok(Some(value.header.event))
                            }
                            EventBody::SessionTurn {
                                text: StoredText::Erased { .. },
                                ..
                            } => Err(scope::unreadable(
                                "mail input capture",
                                "captured bytes were erased before correlation",
                            )),
                            _ => Ok(None),
                        },
                        Read::Absent { .. } => Ok(None),
                        Read::Unknown { what } => {
                            Err(scope::unreadable("mail input capture", &what))
                        }
                        Read::Unreadable { source, reason, .. } => {
                            Err(scope::unreadable(&source, &reason))
                        }
                    }
                })
                .await?;
            if let Some(event) = captured {
                self.confirm_captured(target, flight, &event, deadline)
                    .await?;
                let more = flight.reservation.more_pending;
                let captured_ids = flight.reservation.ids.clone();
                work.mail.flight = None;
                work.mail.backlog = more;
                if more {
                    for id in captured_ids {
                        if !work.mail.seen.contains(&id) {
                            work.mail.seen.push(id);
                        }
                    }
                } else {
                    work.mail.seen.clear();
                }
            }
        }
        let settled = self.settle_mail(target, deadline).await?;
        if work
            .mail
            .flight
            .as_ref()
            .is_some_and(|f| settled.contains(&f.reservation.effect_id))
        {
            work.mail.flight = None;
        }
        if let Some(notice) = previous
            && work.mail.flight.is_none()
            && work.secode.is_some()
        {
            self.retire_secode_notice(work, &notice, deadline).await?;
        }
        Ok(())
    }

    async fn confirm_captured(
        &self,
        target: &core::MailTarget,
        flight: &Flight,
        event: &se_types::EventId,
        deadline: &Deadline,
    ) -> Result<()> {
        let expected = flight.text_sha256;
        let ids = flight.reservation.ids.clone();
        let undelivered = self
            .store
            .read(admission(target), deadline, move |cx| {
                let mut result = Vec::new();
                for id in ids {
                    let message = scope::require_present(
                        cx.read.message(id.clone()).map_err(|e| store_error(&e))?,
                        "reserved mail",
                        scope::COMMITTED_READ_RECOVERY,
                    )?;
                    if message.delivered.is_none() {
                        result.push(id);
                    }
                }
                Ok(result)
            })
            .await?;
        for message in &undelivered {
            let request = core::InputAccepted {
                target: target.clone(),
                effect: flight.reservation.effect_id,
                message: message.clone(),
                evidence: event.clone(),
                accepted_text_sha256: expected,
                key: IdempotencyKey::new(format!(
                    "mail.delivered.{}.{}",
                    se_types::hex_lower(flight.reservation.effect_id.as_bytes()),
                    message.as_str()
                ))?,
            };
            commit::step(
                &self.store,
                admission(target),
                deadline,
                move |kernel, cx| core::confirm_delivery(kernel, cx, request),
                core::observation_committed,
            )
            .await?;
        }
        Ok(())
    }

    async fn settle_mail(
        &self,
        target: &core::MailTarget,
        deadline: &Deadline,
    ) -> Result<Vec<RecordId>> {
        let recipient = target.agent.clone();
        let resolved = self
            .store
            .read(admission(target), deadline, move |cx| {
                let notices = cx
                    .read
                    .mail_notices(recipient.clone(), budget())
                    .map_err(|e| store_error(&e))?;
                if !notices.window().complete() {
                    return Err(scope::unreadable(
                        "mail settlement inventory",
                        "bounded notice inventory is incomplete; preserve unresolved debt",
                    ));
                }
                let mut resolved = Vec::new();
                for record in notices.items() {
                    let original = record.original.as_deref().unwrap_or(&record.current);
                    let EventBody::EffectRequested {
                        effect,
                        intent: se_store::EffectIntent::MailNotice(notice),
                        ..
                    } = &original.body
                    else {
                        return Err(scope::unreadable(
                            "mail settlement",
                            "notice inventory differs from its immutable Bell intent",
                        ));
                    };
                    let mut evidence = Vec::new();
                    for message in &notice.ids {
                        match cx
                            .read
                            .mail_resolution(message.clone(), recipient.clone())
                            .map_err(|e| store_error(&e))?
                        {
                            Read::Present { value } => evidence.push(value.header.event),
                            Read::Absent { .. } => break,
                            Read::Unknown { what } => {
                                return Err(scope::unreadable("mail disposition", &what));
                            }
                            Read::Unreadable { source, reason, .. } => {
                                return Err(scope::unreadable(&source, &reason));
                            }
                        }
                    }
                    if evidence.len() == notice.ids.len() {
                        resolved.push((*effect, evidence));
                    }
                }
                Ok(resolved)
            })
            .await?;
        let mut settled = Vec::with_capacity(resolved.len());
        for (effect, evidence) in resolved {
            let req = core::SettleResolved {
                target: target.clone(),
                effect,
                evidence,
            };
            commit::step(
                &self.store,
                admission(target),
                deadline,
                move |kernel, cx| core::settle_resolved(kernel, cx, req),
                |_, cx, then, r| {
                    core::settlement_committed(cx, then, r).map(|v| Read::Present { value: v })
                },
            )
            .await?;
            settled.push(effect);
        }
        Ok(settled)
    }
}
