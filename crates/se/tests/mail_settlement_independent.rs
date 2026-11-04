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
use std::time::Duration;
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
    let writer = owner.client();
    let sid = session()?;
    wait(writer.submit(f.batch(
        f.owner_project(),
        Some(fixture::request(&format!(
            "fixture-mail_settlement_independent-45-{}",
            serial()
        ))?),
        vec![prepared(&f, &sid, &f.a), activated(&sid)?],
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
    let effect = record()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let k = kernel()?;
    let step = {
        let mut read = reader.snapshot(scope.clone())?;
        reserve_notice(
            &k,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            ReserveNotice {
                target: target.clone(),
                key: request("reserve")?.key,
                notice_id: record()?,
                effect_id: effect,
            },
        )?
    };
    let OpStep::Commit { batch, then } = step else {
        return Err("notice was not planned".into());
    };
    let receipt = wait(writer.submit(batch)?)??;
    let original_reservation = {
        let mut read = reader.snapshot(scope.clone())?;
        let reserved = committed(
            &k,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            then,
            receipt,
        )?;
        assert_eq!(reserved.ids, vec![first.clone(), second.clone()]);
        reserved
    };
    let retry = || -> Result<_, Box<dyn std::error::Error>> {
        let mut read = reader.snapshot(scope.clone())?;
        Ok(reserve_notice(
            &k,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            ReserveNotice {
                target: target.clone(),
                key: request("reserve")?.key,
                notice_id: record()?,
                effect_id: record()?,
            },
        )?)
    };
    let OpStep::Complete(Read::Present {
        value: active_retry,
    }) = retry()?
    else {
        return Err("active reservation retry lost its original work".into());
    };
    assert_eq!(active_retry.effect_id, original_reservation.effect_id);
    assert_eq!(active_retry.notice_id, original_reservation.notice_id);
    assert_eq!(active_retry.ids, original_reservation.ids);
    assert_eq!(active_retry.event_id, original_reservation.event_id);
    // Later messages are outside the immutable reservation and remain new debt.
    let replacement = message()?;
    wait(writer.submit(f.send(
        Actor::Agent(f.b.clone()),
        Actor::Agent(f.a.clone()),
        replacement.clone(),
        "replacement remains unread",
        "replacement",
    )?)?)??;
    let read_event = wait(writer.submit(f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        None,
        vec![EventBody::MessageRead {
            message: first.clone(),
            recipient: Actor::Agent(f.a.clone()),
        }],
    )?)?)??
    .primary_event;
    let plan = |evidence: Vec<EventId>| -> Result<_, Box<dyn std::error::Error>> {
        let mut read = reader.snapshot(scope.clone())?;
        Ok(settle_resolved(
            &kernel()?,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            SettleResolved {
                target: target.clone(),
                effect,
                evidence,
            },
        )?)
    };
    {
        let mut read = reader.snapshot(scope.clone())?;
        assert_eq!(
            present(read.mail_disposition(read_event.clone(), f.a.clone())?)?
                .header
                .event,
            read_event
        );
        assert!(
            read.mail_disposition(read_event.clone(), f.b.clone())
                .is_err()
        );
    }
    {
        let mut other = reader.snapshot(f.self_scope(&f.b))?;
        assert!(
            other
                .mail_disposition(read_event.clone(), f.b.clone())
                .is_err()
        );
        let mut maintenance = reader.snapshot(f.scoped(Visibility::Owner))?;
        assert!(
            maintenance
                .mail_disposition(read_event.clone(), f.a.clone())
                .is_err()
        );
    }
    assert!(
        matches!(
            plan(vec![read_event.clone()])?,
            OpStep::Complete(Read::Absent { .. })
        ),
        "one read incorrectly settled a two-message reservation"
    );
    assert!(plan(vec![read_event.clone(), read_event.clone()]).is_err());
    let mut dismissal = f.batch(
        scope.admission.clone(),
        None,
        vec![EventBody::MessageDismissed {
            message: second.clone(),
            recipient: Actor::Agent(f.a.clone()),
        }],
    )?;
    for event in &mut dismissal.events {
        event.header.session = scope.admission.session.clone();
    }
    let dismissed = wait(writer.submit(dismissal)?)??.primary_event;
    let OpStep::Commit { batch, then } = plan(vec![read_event.clone(), dismissed.clone()])? else {
        return Err("all original IDs resolved but settlement was not planned".into());
    };
    let receipt = wait(writer.submit(batch)?)??;
    let settled = {
        let mut read = reader.snapshot(scope.clone())?;
        settlement_committed(
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            then,
            receipt,
        )?
    };
    assert!(
        matches!(plan(vec![])?, OpStep::Complete(Read::Present { value }) if value.event_id == settled.event_id),
        "replay did not retain the original committed settlement"
    );
    for _ in 0..2 {
        let refusal = retry()
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
    {
        let mut read = reader.snapshot(scope.clone())?;
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
            read.mail_notices(f.a.clone(), budget(10, 65536, None)?)?
                .items()
                .is_empty()
        );
    }
    // A new request must still reserve later unread mail, without resurrecting
    // the terminal effect or changing its stable settlement receipt.
    let fresh_effect = record()?;
    let fresh_kernel = kernel()?;
    let fresh_step = {
        let mut read = reader.snapshot(scope.clone())?;
        reserve_notice(
            &fresh_kernel,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            ReserveNotice {
                target: target.clone(),
                key: request("reserve-later")?.key,
                notice_id: record()?,
                effect_id: fresh_effect,
            },
        )?
    };
    let OpStep::Commit { batch, then } = fresh_step else {
        return Err("fresh key did not plan the remaining unread mail".into());
    };
    let receipt = wait(writer.submit(batch)?)??;
    {
        let mut read = reader.snapshot(scope.clone())?;
        let fresh = committed(
            &fresh_kernel,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            then,
            receipt,
        )?;
        assert_eq!(fresh.effect_id, fresh_effect);
        assert_ne!(fresh.effect_id, effect);
        assert_ne!(fresh.notice_id, original_reservation.notice_id);
        assert_eq!(fresh.ids, vec![replacement]);
        assert_eq!(
            read.mail_notices(f.a.clone(), budget(10, 65536, None)?)?
                .items()
                .len(),
            1
        );
    }
    assert!(
        matches!(plan(vec![])?, OpStep::Complete(Read::Present { value }) if value.event_id == settled.event_id),
        "fresh reservation changed the original settlement replay"
    );
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}
