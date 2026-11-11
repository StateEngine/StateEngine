//! Notification intent and observations through the real store/core consumers.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    commit::{Cx, OpStep},
    dispatch::{CallFacts, Kernel},
    ops::mail::*,
};
use se_store::{
    mail::{MailSnapshot, OfferObservation, OfferReport},
    *,
};
use se_types::{WorkAction, WorkAddressing};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "Shared session fixture also supplies capture operations."
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
fn quiet(f: &Fixture, id: se_types::MessageId) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut batch = f.send(
        Actor::Human(f.owner.clone()),
        Actor::Agent(f.a.clone()),
        id,
        "quiet but unread",
        "quiet-send",
    )?;
    let EventBody::MessageSent { quiet, .. } = &mut batch.events[0].body else {
        return Err("wrong fixture message".into());
    };
    *quiet = true;
    Ok(batch)
}
#[test]
fn quiet_direct_and_work_intent_survive_replay_and_reopen_without_hiding_unread_mail() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let id = message()?;
    let first = store.append(quiet(&f, id.clone())?, &*lease)?;
    let again = store.append(quiet(&f, id.clone())?, &*lease)?;
    same_receipt(&first, &again);
    assert!(
        first.wakes.is_empty() && again.wakes.is_empty(),
        "quiet send or replay emitted a wake"
    );
    let floor = message()?;
    let sent = store.append(
        f.batch(
            f.owner_project(),
            Some(request("quiet-floor")?),
            vec![EventBody::WorkMessageSent {
                quiet: true,
                message: floor.clone(),
                work: WorkAddressing {
                    action: WorkAction::Finding,
                    addressees: vec![f.a.clone(), f.b.clone()],
                },
                kind: "finding".into(),
                body: InputText::Inline("quiet shared work".into()),
                refs: vec![],
                reply_to: None,
            }],
        )?,
        &*lease,
    )?;
    assert!(sent.wakes.is_empty());
    store.close()?;
    let store = present(SqliteFactory::open_direct(&f.options, &*lease)?)?;
    let mut a = store.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        a.message_count(query(Some(Actor::Agent(f.a.clone())), true))?,
        2
    );
    assert!(
        a.mail_pending(f.a.clone(), budget(1, 65536, None)?)?
            .items()
            .is_empty(),
        "quiet debt became a notification after reopen"
    );
    for key in [&id, &floor] {
        let row = present(a.message(key.clone())?)?;
        assert!(row.quiet && row.read.is_none() && row.delivered.is_none());
        assert_eq!(
            row.notifications.len(),
            1,
            "recipient inspection exposed another recipient outcome"
        );
        assert_eq!(row.notifications[0].recipient, Actor::Agent(f.a.clone()));
        assert_eq!(row.notifications[0].state, "quiet");
        assert!(row.notifications[0].event.is_some());
    }
    a.close()?;
    let mut b = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(
        b.message(id)
            .err()
            .ok_or("outsider read unexpectedly succeeded")?
            .code,
        StoreErrorCode::ScopeMismatch
    );
    assert_eq!(present(b.message(floor.clone())?)?.notifications.len(), 1);
    b.close()?;
    let mut owner = store.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        present(owner.message(floor)?)?.notifications.len(),
        2,
        "owner inspection lost an addressed notification"
    );
    owner.close()?;
    store.close()?;
    Ok(())
}
#[test]
fn quiet_prefix_cannot_hide_new_notification_debt_or_change_read_marks() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let mut batch = Vec::new();
    for _ in 0..40 {
        let quiet = quiet(&f, message()?)?;
        batch.push(quiet.events.into_iter().next().ok_or("quiet event")?.body);
    }
    store.append(
        f.batch(f.owner_project(), Some(request("quiet-prefix")?), batch)?,
        &*lease,
    )?;
    let id = message()?;
    store.append(
        f.send(
            Actor::Human(f.owner.clone()),
            Actor::Agent(f.a.clone()),
            id.clone(),
            "wake this one",
            "normal",
        )?,
        &*lease,
    )?;
    let mut a = store.snapshot(f.self_scope(&f.a))?;
    let pending = a.mail_pending(f.a.clone(), budget(1, 65536, None)?)?;
    assert_eq!(pending.items().len(), 1);
    assert_eq!(pending.items()[0].message, id);
    assert_eq!(pending.items()[0].notifications[0].state, "pending");
    assert_eq!(
        a.message_count(query(Some(Actor::Agent(f.a.clone())), true))?,
        41
    );
    assert!(present(a.message(id)?)?.read.is_none());
    a.close()?;
    store.close()?;
    Ok(())
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn notification_failure_retry_and_observation_are_per_recipient_and_never_read_marks() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let writer = owner.client();
    let sid = session()?;
    wait(writer.submit(f.batch(
        f.owner_project(),
        Some(request("session")?),
        vec![prepared(&f, &sid, &f.a), activated(&sid)?],
    )?)?)??;
    let id = message()?;
    wait(writer.submit(f.batch(
        f.owner_project(),
        Some(request("work")?),
        vec![EventBody::WorkMessageSent {
            quiet: false,
            message: id.clone(),
            work: WorkAddressing {
                action: WorkAction::Finding,
                addressees: vec![f.a.clone(), f.b.clone()],
            },
            kind: "finding".into(),
            body: InputText::Inline("two independent wake outcomes".into()),
            refs: vec![],
            reply_to: None,
        }],
    )?)?)??;
    let mut scope = f.self_scope(&f.a);
    scope.admission.session = Some(sid.clone());
    let target = MailTarget {
        project: f.project.clone(),
        agent: f.a.clone(),
        session: sid,
        epoch: epoch()?,
        generation: 1,
        fingerprint: [9; 32],
    };
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let k = kernel()?;
    let effect = record()?;
    let notice_id = record()?;
    let reserve = ReserveNotice {
        target: target.clone(),
        key: request("reserve")?.key,
        notice_id,
        effect_id: effect,
    };
    let step = {
        let mut read = reader.snapshot(scope.clone())?;
        reserve_notice(
            &k,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            reserve,
        )?
    };
    let OpStep::Commit { batch, then } = step else {
        return Err("reservation not planned".into());
    };
    let receipt = wait(writer.submit(batch)?)??;
    let reservation = {
        let mut read = reader.snapshot(scope.clone())?;
        committed(
            &k,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
            then,
            receipt,
        )?
    };
    assert_eq!(reservation.ids, vec![id.clone()]);
    let states = [
        (
            "failed",
            OfferReport::Failed {
                code: "zero-byte-write".into(),
            },
        ),
        ("held", OfferReport::Held),
        (
            "unknown",
            OfferReport::Unknown {
                code: "acceptance-unknown".into(),
            },
        ),
        (
            "offered",
            OfferReport::NativeAdmitted {
                event_id: "native-admission".into(),
                sequence: 1,
            },
        ),
    ];
    for (state, report) in states {
        let k = kernel()?;
        let request = ObserveOffer {
            target: target.clone(),
            effect,
            attempt: record()?,
            evidence: OfferObservation {
                version: 1,
                notice_id,
                target_agent: f.a.clone(),
                session: target.session.clone(),
                epoch: target.epoch.clone(),
                generation: 1,
                fingerprint: target.fingerprint,
                observed_at_us: 1_700_000_000_000_000,
                digest: *reservation.digest.as_bytes(),
                report,
            },
        };
        let step = {
            let mut read = reader.snapshot(scope.clone())?;
            observe_offer(
                &k,
                &mut Cx {
                    read: &mut read,
                    admission: &scope.admission,
                },
                request,
            )?
        };
        let OpStep::Commit { batch, then } = step else {
            return Err("observation not planned".into());
        };
        let receipt = wait(writer.submit(batch)?)??;
        {
            let mut read = reader.snapshot(scope.clone())?;
            observation_committed(
                &k,
                &mut Cx {
                    read: &mut read,
                    admission: &scope.admission,
                },
                then,
                receipt,
            )?;
        }
        let mut inspect = reader.snapshot(f.scoped(Visibility::Owner))?;
        let row = present(inspect.message(id.clone())?)?;
        assert!(row.read.is_none() && row.delivered.is_none());
        assert_eq!(row.notifications.len(), 2);
        for n in row.notifications {
            assert_eq!(
                n.state,
                if n.recipient == Actor::Agent(f.a.clone()) {
                    state
                } else {
                    "pending"
                }
            );
        }
        inspect.close()?;
    }
    let mut a = reader.snapshot(scope)?;
    assert_eq!(
        a.message_count(query(Some(Actor::Agent(f.a.clone())), true))?,
        1
    );
    a.close()?;
    drop(wait(owner.drain(std::time::Duration::from_secs(3)))??);
    Ok(())
}
