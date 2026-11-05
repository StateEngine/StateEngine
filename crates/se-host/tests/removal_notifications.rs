//! Removal abandons notification work, never durable mail or unrelated effects.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    commit::Cx,
    dispatch::{CallFacts, Kernel},
    ops::remove_commit,
};
use se_store::*;
use se_types::IdempotencyKey;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

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
fn debt(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    mail: bool,
) -> Result<(RecordId, se_types::MessageId), Box<dyn std::error::Error>> {
    let id = message()?;
    let sent = d.append(
        f.send(
            Actor::Human(f.owner.clone()),
            Actor::Agent(f.a.clone()),
            id.clone(),
            "Keep this exact unread mail.",
            &format!("send-{}", serial()),
        )?,
        lease,
    )?;
    let effect = RecordId::from_parts(1_700_000_000_000 + serial(), [72; 10])?;
    let intent = if mail {
        EffectIntent::Mail {
            message: id.clone(),
            recipient: Actor::Agent(f.a.clone()),
        }
    } else {
        EffectIntent::Runtime { generation: 1 }
    };
    d.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("effect-{}", serial()))?),
            vec![EventBody::EffectRequested {
                effect,
                principal: Some(Actor::Agent(f.a.clone())),
                kind: if mail {
                    EffectKind::Bell
                } else {
                    EffectKind::RuntimeStart
                },
                intent,
                cause: sent.primary_event,
                request_key: IdempotencyKey::new(format!("request-{}", serial()))?,
            }],
        )?,
        lease,
    )?;
    Ok((effect, id))
}
fn read_effect(
    f: &Fixture,
    d: &SqliteDirect,
    effect: RecordId,
) -> Result<ProjectionRecord, Box<dyn std::error::Error>> {
    let mut read = d.snapshot(f.scoped(Visibility::Owner))?;
    let result = present(read.effect(effect)?)?;
    read.close()?;
    Ok(result)
}
fn abandon(f: &Fixture, d: &mut SqliteDirect, lease: &Lease, effect: RecordId) -> Check {
    let record = read_effect(f, d, effect)?;
    let admission = f.owner_project();
    let mut read = d.snapshot(f.scoped(Visibility::Owner))?;
    let batch = remove_commit::abandon_notification(
        &kernel()?,
        &IdempotencyKey::new("remove-original-key")?,
        record,
        &Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    read.close()?;
    d.append(batch, lease)?;
    Ok(())
}
#[test]
fn removal_abandons_legacy_notification_without_marking_or_erasing_mail() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (effect, id) = debt(&f, &mut d, &lease, true)?;
    abandon(&f, &mut d, &lease, effect)?;
    let head = read_effect(&f, &d, effect)?;
    assert!(
        matches!(head.current.body,EventBody::EffectSettled { outcome:EffectOutcome::Abandoned, ref evidence, ref failure,.. } if evidence.is_empty() && failure.as_ref().is_some_and(|s|s.contains("without claiming delivery")))
    );
    let mut read = d.snapshot(f.scoped(Visibility::Owner))?;
    let message = present(read.message(id)?)?;
    assert!(message.read.is_none() && message.dismissed.is_none() && message.delivered.is_none());
    assert!(
        matches!(message.body,StoredText::Present(ref body) if body=="Keep this exact unread mail.")
    );
    assert!(
        remove_commit::pending_effects(&mut Cx {
            read: &mut read,
            admission: &f.owner_project()
        })?
        .is_empty()
    );
    read.close()?;
    d.close()?;
    drop(lease);
    Ok(())
}
#[test]
fn non_notification_debt_is_not_retired_and_still_blocks_removal() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (effect, _) = debt(&f, &mut d, &lease, false)?;
    let record = read_effect(&f, &d, effect)?;
    assert!(!remove_commit::is_mail_notification(&record));
    assert!(abandon(&f, &mut d, &lease, effect).is_err());
    let mut read = d.snapshot(f.scoped(Visibility::Owner))?;
    let registration = present(read.project(f.project.clone())?)?;
    read.close()?;
    let key = IdempotencyKey::new("remove-with-unrelated-debt")?;
    let mut read = d.snapshot(f.scoped(Visibility::Owner))?;
    let batch = remove_commit::tombstone(
        &kernel()?,
        &key,
        f.project.clone(),
        registration.revision,
        vec![registration.current.header.event],
        &Cx {
            read: &mut read,
            admission: &f.owner_project(),
        },
    )?;
    read.close()?;
    assert!(
        d.append(batch, &*lease).is_err(),
        "pending runtime effect was hidden by removal"
    );
    assert!(matches!(
        read_effect(&f, &d, effect)?.current.body,
        EventBody::EffectRequested { .. }
    ));
    d.close()?;
    drop(lease);
    Ok(())
}
#[test]
fn another_agent_cannot_abandon_the_recipient_notification() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (effect, _) = debt(&f, &mut d, &lease, true)?;
    let record = read_effect(&f, &d, effect)?;
    let admission = f.self_scope(&f.b).admission;
    let mut read = d.snapshot(f.self_scope(&f.b))?;
    let batch = remove_commit::abandon_notification(
        &kernel()?,
        &IdempotencyKey::new("foreign-remove")?,
        record,
        &Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    read.close()?;
    assert!(
        d.append(batch, &*lease).is_err(),
        "foreign agent abandoned another recipient's notification"
    );
    assert!(matches!(
        read_effect(&f, &d, effect)?.current.body,
        EventBody::EffectRequested { .. }
    ));
    d.close()?;
    drop(lease);
    Ok(())
}
