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
        let previous = work
            .mail
            .flight
            .as_ref()
            .map(|f| f.reservation.notice_id.clone());
        self.clear_settled_flight(&mut work.mail.flight, target, deadline)
            .await?;
        let Some(flight) = work.mail.flight.as_mut() else {
            if work.secode.is_some()
                && let Some(notice) = previous
            {
                self.retire_secode_notice(work, &notice, deadline).await?;
            }
            return self.reconcile_captured_mail(work, target, deadline).await;
        };
        let evidence = flight.evidence.clone().ok_or_else(|| {
            scope::unreadable("mail transport outcome", "the retained write attempt is unproved; preserve pending mail and stop/relaunch the binding before another offer")
        })?;
        if !flight.observed {
            let req = core::ObserveOffer {
                target: target.clone(),
                effect: flight.reservation.effect_id,
                attempt: flight.attempt,
                evidence,
            };
            commit::step(
                &self.store,
                admission(target),
                deadline,
                move |k, cx| core::observe_offer(k, cx, req),
                core::observation_committed,
            )
            .await?;
            flight.observed = true;
        }
        // Preserve the attempted offer before an authenticated read can fail.
        if work.secode.is_some() {
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
            .map(|f| f.reservation.notice_id.clone());
        self.clear_settled_flight(&mut work.mail.flight, target, deadline)
            .await?;
        if let Some(flight) = work.mail.flight.as_mut() {
            // Only a witnessed zero-byte failure permits a fresh attempt on a
            // later commit/retry wake. Uncertain acceptance retains this flight.
            if flight
                .evidence
                .as_ref()
                .is_some_and(|e| matches!(e.report, se_store::mail::OfferReport::Failed { .. }))
            {
                work.mail.flight = None;
                self.settle_mail(&mut work.mail.flight, target, deadline)
                    .await?;
                return Ok(());
            }
            let (recipient, session) = (target.agent.clone(), target.session.clone());
            let (through, expected) = (flight.reservation.through.clone(), flight.text_sha256);
            let captured = self
                .store
                .read(admission(target), deadline, move |cx| {
                    let pos = cx
                        .read
                        .cursor_position(&through, PositionPurpose::Checked)
                        .map_err(|e| store_error(&e))?;
                    match cx
                        .read
                        .mail_input(recipient, session, pos, expected, Duration::from_secs(1))
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
                let (more, mut ids) = (
                    flight.reservation.more_pending,
                    flight.reservation.ids.clone(),
                );
                work.mail.flight = None;
                work.mail.backlog = more;
                if more {
                    ids.retain(|id| !work.mail.seen.contains(id));
                    work.mail.seen.extend(ids);
                } else {
                    work.mail.seen.clear();
                }
            }
        }
        self.settle_mail(&mut work.mail.flight, target, deadline)
            .await?;
        if work.mail.flight.is_none()
            && work.secode.is_some()
            && let Some(notice) = previous
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
        let (expected, ids) = (flight.text_sha256, flight.reservation.ids.clone());
        let undelivered = self
            .store
            .read(admission(target), deadline, move |cx| {
                let mut out = Vec::new();
                for id in ids {
                    let msg = scope::require_present(
                        cx.read.message(id.clone()).map_err(|e| store_error(&e))?,
                        "reserved mail",
                        scope::COMMITTED_READ_RECOVERY,
                    )?;
                    if msg.delivered.is_none() {
                        out.push(id);
                    }
                }
                Ok(out)
            })
            .await?;
        let effect = flight.reservation.effect_id;
        let hex = se_types::hex_lower(effect.as_bytes());
        for message in undelivered {
            let req = core::InputAccepted {
                key: IdempotencyKey::new(format!("mail.delivered.{hex}.{}", message.as_str()))?,
                target: target.clone(),
                effect,
                message,
                evidence: event.clone(),
                accepted_text_sha256: expected,
            };
            commit::step(
                &self.store,
                admission(target),
                deadline,
                move |k, cx| core::confirm_delivery(k, cx, req),
                core::observation_committed,
            )
            .await?;
        }
        Ok(())
    }

    async fn settle_mail(
        &self,
        flight: &mut Option<Flight>,
        target: &core::MailTarget,
        deadline: &Deadline,
    ) -> Result<()> {
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
        let mut step = Ok(());
        for (effect, evidence) in resolved {
            let req = core::SettleResolved {
                target: target.clone(),
                effect,
                evidence,
            };
            step = commit::step(
                &self.store,
                admission(target),
                deadline,
                move |k, cx| core::settle_resolved(k, cx, req),
                |_, cx, t, r| {
                    core::settlement_committed(cx, t, r).map(|v| Read::Present { value: v })
                },
            )
            .await
            .map(|_| ());
            if step.is_err() {
                break;
            }
        }
        self.clear_settled_flight(flight, target, deadline).await?;
        step
    }

    /// Clear `flight` directly when its effect is already settled, before any
    /// fallible replay, capture, or pending-inventory read can fail.
    async fn clear_settled_flight(
        &self,
        flight: &mut Option<Flight>,
        target: &core::MailTarget,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(effect) = flight.as_ref().map(|f| f.reservation.effect_id) else {
            return Ok(());
        };
        if self
            .store
            .read(admission(target), deadline, move |cx| {
                let rec = scope::require_present(
                    cx.read.effect(effect).map_err(|e| store_error(&e))?,
                    "mail flight effect",
                    scope::COMMITTED_READ_RECOVERY,
                )?;
                Ok(matches!(rec.current.body, EventBody::EffectSettled { .. }))
            })
            .await?
        {
            *flight = None;
        }
        Ok(())
    }
}
