//! Independent real-store judge: recipient read/dismiss resolves only the
//! complete original notice, preserving later unread mail and stable replay.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    commit::{Cx, OpStep},
    dispatch::{CallFacts, Kernel},
    ops::mail::*,
};
use se_store::{mail::MailSnapshot, *};
use se_types::{EventId, Read};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "Shared session fixture also serves capture judges."
)]
mod capture_fixture;
use capture_fixture::{activated, prepared, record, session};

fn kernel() -> Result<Kernel, Box<dyn std::error::Error>> {
    Ok(Kernel::new(CallFacts {
        event: event()?,
        message: message()?,
        agent: agent()?,
        profile_event: event()?,
        notification_event: event()?,
        notification_message: message()?,
        occurred_at_us: 1_700_000_000_000_000,
        door: Door::Cli,
    })?)
}

/// Bug: a09b427b — a settled reservation request was returned as live delivery work.
#[test]
fn actual_recipient_read_and_dismiss_settle_only_complete_original_debt() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let (mailbox, first, second) = seed_mailbox(&f, owner.client())?;
    let effect = record()?;
    let k = kernel()?;
    let original_reservation = mailbox.reserve(&k, "reserve", effect, "notice was not planned")?;
    assert_eq!(
        original_reservation.ids,
        vec![first.clone(), second.clone()]
    );
    let OpStep::Complete(Read::Present {
        value: active_retry,
    }) = mailbox.retry()?
    else {
        return Err("active reservation retry lost its original work".into());
    };
    assert_eq!(active_retry.effect_id, original_reservation.effect_id);
    assert_eq!(active_retry.notice_id, original_reservation.notice_id);
    assert_eq!(active_retry.ids, original_reservation.ids);
    assert_eq!(active_retry.event_id, original_reservation.event_id);
    // Later messages are outside the immutable reservation and remain new debt.
    let replacement = message()?;
    wait(mailbox.writer.submit(f.send(
        Actor::Agent(f.b.clone()),
        Actor::Agent(f.a.clone()),
        replacement.clone(),
        "replacement remains unread",
        "replacement",
    )?)?)??;
    let read_event = wait(mailbox.writer.submit(f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        None,
        vec![EventBody::MessageRead {
            message: first.clone(),
            recipient: Actor::Agent(f.a.clone()),
        }],
    )?)?)??
    .primary_event;
    mailbox.dispositions_are_recipient_scoped(&read_event)?;
    assert!(
        matches!(
            mailbox.plan(effect, vec![read_event.clone()])?,
            OpStep::Complete(Read::Absent { .. })
        ),
        "one read incorrectly settled a two-message reservation"
    );
    assert!(
        mailbox
            .plan(effect, vec![read_event.clone(), read_event.clone()])
            .is_err()
    );
    let dismissed = mailbox.dismiss(&second)?;
    let settled = mailbox.settle(effect, vec![read_event.clone(), dismissed.clone()])?;
    assert!(
        matches!(mailbox.plan(effect, vec![])?, OpStep::Complete(Read::Present { value }) if value.event_id == settled.event_id),
        "replay did not retain the original committed settlement"
    );
    mailbox.settled_retries_refuse()?;
    mailbox.markers_after_settlement(first, second, effect, read_event, &replacement)?;
    // A new request must still reserve later unread mail, without resurrecting
    // the terminal effect or changing its stable settlement receipt.
    let fresh_effect = record()?;
    let fresh_kernel = kernel()?;
    let fresh = mailbox.reserve(
        &fresh_kernel,
        "reserve-later",
        fresh_effect,
        "fresh key did not plan the remaining unread mail",
    )?;
    assert_eq!(fresh.effect_id, fresh_effect);
    assert_ne!(fresh.effect_id, effect);
    assert_ne!(fresh.notice_id, original_reservation.notice_id);
    assert_eq!(fresh.ids, vec![replacement]);
    {
        let mut read = mailbox.reader.snapshot(mailbox.scope.clone())?;
        assert_eq!(
            read.mail_notices(f.a.clone(), budget(10, 65536, None)?)?
                .items()
                .len(),
            1
        );
    }
    assert!(
        matches!(mailbox.plan(effect, vec![])?, OpStep::Complete(Read::Present { value }) if value.event_id == settled.event_id),
        "fresh reservation changed the original settlement replay"
    );
    drop(wait_drained(owner.drain(DRAIN_DEADLINE))??);
    Ok(())
}

/// The recipient's live mail target, the real writer and an outside reader.
struct Mailbox<'a> {
    f: &'a Fixture,
    writer: SqliteClient,
    reader: SqliteReader,
    scope: ReadScope,
    target: MailTarget,
}

/// Launch the recipient's session and leave two unread messages for it.
fn seed_mailbox(
    f: &Fixture,
    writer: SqliteClient,
) -> Result<(Mailbox<'_>, se_types::MessageId, se_types::MessageId), Box<dyn std::error::Error>> {
    let sid = session()?;
    wait(writer.submit(f.batch(
        f.owner_project(),
        Some(fixture::request(&format!(
            "fixture-mail_settlement_independent-45-{}",
            serial()
        ))?),
        vec![prepared(f, &sid, &f.a), activated(&sid)?],
    )?)?)??;
    let first = message()?;
    let second = message()?;
    for (id, key) in [(&first, "first"), (&second, "second")] {
        wait(writer.submit(f.send(
            Actor::Agent(f.b.clone()),
            Actor::Agent(f.a.clone()),
            id.clone(),
            "unread recipient message",
            key,
        )?)?)??;
    }
    let mut scope = f.self_scope(&f.a);
    scope.admission.session = Some(sid.clone());
    let target = MailTarget {
        project: f.project.clone(),
        agent: f.a.clone(),
        session: sid,
        epoch: epoch()?,
        generation: 1,
        fingerprint: [7; 32],
    };
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mailbox = Mailbox {
        f,
        writer,
        reader,
        scope,
        target,
    };
    Ok((mailbox, first, second))
}

impl Mailbox<'_> {
    /// Plan a notice reservation under `key`, commit it and read it back.
    fn reserve(
        &self,
        kernel: &Kernel,
        key: &str,
        effect: RecordId,
        unplanned: &str,
    ) -> Result<Reservation, Box<dyn std::error::Error>> {
        let step = {
            let mut read = self.reader.snapshot(self.scope.clone())?;
            reserve_notice(
                kernel,
                &mut Cx {
                    read: &mut read,
                    admission: &self.scope.admission,
                },
                ReserveNotice {
                    target: self.target.clone(),
                    key: request(key)?.key,
                    notice_id: record()?,
                    effect_id: effect,
                },
            )?
        };
        let OpStep::Commit { batch, then } = step else {
            return Err(unplanned.into());
        };
        let receipt = wait(self.writer.submit(batch)?)??;
        let mut read = self.reader.snapshot(self.scope.clone())?;
        Ok(committed(
            kernel,
            &mut Cx {
                read: &mut read,
                admission: &self.scope.admission,
            },
            then,
            receipt,
        )?)
    }
    /// Retry the original reservation key with fresh notice and effect IDs.
    fn retry(&self) -> Result<OpStep<Read<Reservation>, MailThen>, Box<dyn std::error::Error>> {
        let mut read = self.reader.snapshot(self.scope.clone())?;
        Ok(reserve_notice(
            &kernel()?,
            &mut Cx {
                read: &mut read,
                admission: &self.scope.admission,
            },
            ReserveNotice {
                target: self.target.clone(),
                key: request("reserve")?.key,
                notice_id: record()?,
                effect_id: record()?,
            },
        )?)
    }
    /// Plan settling the original effect from the given resolution evidence.
    fn plan(
        &self,
        effect: RecordId,
        evidence: Vec<EventId>,
    ) -> Result<OpStep<Read<Settlement>, SettlementThen>, Box<dyn std::error::Error>> {
        let mut read = self.reader.snapshot(self.scope.clone())?;
        Ok(settle_resolved(
            &kernel()?,
            &mut Cx {
                read: &mut read,
                admission: &self.scope.admission,
            },
            SettleResolved {
                target: self.target.clone(),
                effect,
                evidence,
            },
        )?)
    }
    /// Only the recipient's own scope may read its mail disposition.
    fn dispositions_are_recipient_scoped(&self, read_event: &EventId) -> Check {
        let f = self.f;
        {
            let mut read = self.reader.snapshot(self.scope.clone())?;
            assert_eq!(
                present(read.mail_disposition(read_event.clone(), f.a.clone())?)?
                    .header
                    .event,
                *read_event
            );
            assert!(
                read.mail_disposition(read_event.clone(), f.b.clone())
                    .is_err()
            );
        }
        let mut other = self.reader.snapshot(f.self_scope(&f.b))?;
        assert!(
            other
                .mail_disposition(read_event.clone(), f.b.clone())
                .is_err()
        );
        let mut maintenance = self.reader.snapshot(f.scoped(Visibility::Owner))?;
        assert!(
            maintenance
                .mail_disposition(read_event.clone(), f.a.clone())
                .is_err()
        );
        Ok(())
    }
    /// The recipient dismisses `message` in its own session.
    fn dismiss(
        &self,
        message: &se_types::MessageId,
    ) -> Result<EventId, Box<dyn std::error::Error>> {
        let mut dismissal = self.f.batch(
            self.scope.admission.clone(),
            None,
            vec![EventBody::MessageDismissed {
                message: message.clone(),
                recipient: Actor::Agent(self.f.a.clone()),
            }],
        )?;
        for event in &mut dismissal.events {
            event.header.session = self.scope.admission.session.clone();
        }
        Ok(wait(self.writer.submit(dismissal)?)??.primary_event)
    }
    /// Commit the settlement once every original ID is resolved, and read it back.
    fn settle(
        &self,
        effect: RecordId,
        evidence: Vec<EventId>,
    ) -> Result<Settlement, Box<dyn std::error::Error>> {
        let OpStep::Commit { batch, then } = self.plan(effect, evidence)? else {
            return Err("all original IDs resolved but settlement was not planned".into());
        };
        let receipt = wait(self.writer.submit(batch)?)??;
        let mut read = self.reader.snapshot(self.scope.clone())?;
        Ok(settlement_committed(
            &mut Cx {
                read: &mut read,
                admission: &self.scope.admission,
            },
            then,
            receipt,
        )?)
    }
    /// Retrying the settled reservation refuses as a state conflict, twice.
    fn settled_retries_refuse(&self) -> Check {
        for _ in 0..2 {
            let refusal = self
                .retry()
                .err()
                .ok_or("settled reservation retry returned old delivery work")?;
            let refusal = refusal
                .downcast_ref::<se_types::SeError>()
                .ok_or("reservation retry lost its structured refusal")?;
            let se_types::Detail::StateConflict(conflict) = refusal.body.detail() else {
                return Err("settled reservation retry refused for an unrelated reason".into());
            };
            assert!(conflict.reason.contains("settled"));
            assert!(conflict.next_step.contains("fresh"));
        }
        Ok(())
    }
    /// Settlement keeps exactly the recipient's own markers and leaves later
    /// mail untouched, with no notice left to deliver.
    fn markers_after_settlement(
        &self,
        first: se_types::MessageId,
        second: se_types::MessageId,
        effect: RecordId,
        read_event: EventId,
        replacement: &se_types::MessageId,
    ) -> Check {
        let mut read = self.reader.snapshot(self.scope.clone())?;
        let original = present(read.message(first)?)?;
        assert!(original.read.is_some(), "resolution lost a read marker");
        assert!(
            original.dismissed.is_none(),
            "resolution invented a dismiss marker"
        );
        let other = present(read.message(second)?)?;
        assert!(other.read.is_none() && other.dismissed.is_some());
        let record = present(read.effect(effect)?)?;
        assert!(
            matches!(record.current.body, EventBody::EffectSettled { outcome: EffectOutcome::Witnessed, evidence, .. }
            if evidence == vec![read_event])
        );
        let later = present(read.message(replacement.clone())?)?;
        assert!(later.read.is_none() && later.dismissed.is_none() && later.delivered.is_none());
        assert!(
            read.mail_notices(self.f.a.clone(), budget(10, 65536, None)?)?
                .items()
                .is_empty()
        );
        Ok(())
    }
}
