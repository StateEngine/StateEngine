use se_store::mail::MailSnapshot;
use se_store::*;
use se_types::{WorkAction, WorkAddressing};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn work(
    f: &Fixture,
    id: se_types::MessageId,
    addressees: Vec<se_types::AgentId>,
    key: &str,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    f.batch(
        f.owner_project(),
        Some(request(key)?),
        vec![EventBody::WorkMessageSent {
            message: id,
            work: WorkAddressing {
                action: WorkAction::Finding,
                addressees,
            },
            kind: "finding".into(),
            body: InputText::Inline("shared complete body".into()),
            refs: vec![],
            reply_to: None,
        }],
    )
}

#[test]
fn one_work_message_has_independent_recipient_dispositions_and_natural_replays() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let id = message()?;
    let sent = store.append(
        work(&f, id.clone(), vec![f.a.clone(), f.b.clone()], "work")?,
        &*lease,
    )?;
    assert_eq!(sent.wakes.len(), 2);
    for agent in [&f.a, &f.b] {
        let mut s = store.snapshot(f.self_scope(agent))?;
        assert_eq!(
            s.message_count(query(Some(Actor::Agent(agent.clone())), true))?,
            1
        );
        let row = present(s.message(id.clone())?)?;
        assert_eq!(row.event, sent.primary_event);
        assert_eq!(row.recipient, Actor::Agent(agent.clone()));
        assert_eq!(row.work.ok_or("missing work address")?.addressees.len(), 2);
        assert!(matches!(row.body,StoredText::Present(body) if body=="shared complete body"));
        s.close()?;
    }
    let read = || {
        f.batch(
            f.self_scope(&f.a).admission,
            None,
            vec![EventBody::MessageRead {
                message: id.clone(),
                recipient: Actor::Agent(f.a.clone()),
            }],
        )
    };
    let first = store.append(read()?, &*lease)?;
    let again = store.append(read()?, &*lease)?;
    same_receipt(&first, &again);
    assert_eq!(again.state, CommitState::NaturalKeyReplay);
    let mut a = store.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        a.message_count(query(Some(Actor::Agent(f.a.clone())), true))?,
        0
    );
    let disposition = present(a.mail_disposition(first.primary_event.clone(), f.a.clone())?)?;
    assert!(matches!(disposition.body, EventBody::MessageRead { .. }));
    a.close()?;
    let mut b = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(
        b.message_count(query(Some(Actor::Agent(f.b.clone())), true))?,
        1
    );
    assert!(present(b.message(id.clone())?)?.read.is_none());
    b.close()?;
    let mut owner = store.snapshot(f.scoped(Visibility::Owner))?;
    for (agent, was_read) in [(&f.a, true), (&f.b, false)] {
        let page = owner.messages(
            query(Some(Actor::Agent(agent.clone())), false),
            budget(10, 65536, None)?,
        )?;
        let row = page.items().first().ok_or("missing selected delivery")?;
        assert_eq!(row.recipient, Actor::Agent(agent.clone()));
        assert_eq!(row.read.is_some(), was_read);
    }
    let row = present(owner.message(id.clone())?)?;
    assert_eq!(row.recipient, Actor::Agent(f.a.clone()));
    assert!(row.read.is_some());
    owner.close()?;
    store.append(
        f.batch(
            f.self_scope(&f.b).admission,
            None,
            vec![EventBody::MessageDismissed {
                message: id.clone(),
                recipient: Actor::Agent(f.b.clone()),
            }],
        )?,
        &*lease,
    )?;
    let mut b = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(
        b.message_count(query(Some(Actor::Agent(f.b.clone())), true))?,
        0
    );
    b.close()?;
    store.close()?;
    Ok(())
}

#[test]
fn work_delivery_fanout_cannot_hide_messages_at_a_page_boundary() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    for n in 0..3 {
        store.append(
            work(
                &f,
                message()?,
                vec![f.a.clone(), f.b.clone()],
                &format!("page-{n}"),
            )?,
            &*lease,
        )?;
    }
    let mut s = store.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(s.message_count(query(None, false))?, 3);
    let mut cursor = None;
    let mut ids = Vec::new();
    loop {
        let page = s.messages(query(None, false), budget(1, 65536, cursor)?)?;
        cursor = page.next().cloned();
        ids.extend(page.into_items().into_iter().map(|m| m.message));
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids.len(), 3);
    assert!(ids.iter().enumerate().all(|(n, id)| !ids[..n].contains(id)));
    s.close()?;
    store.close()?;
    Ok(())
}

#[test]
fn invalid_work_recipients_roll_back_every_delivery_and_foreign_reads_refuse() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let before = store.info()?.head;
    for addressees in [
        vec![f.a.clone(), agent()?],
        vec![f.a.clone(), f.a.clone()],
        vec![],
    ] {
        assert!(
            store
                .append(
                    work(&f, message()?, addressees, &format!("bad-{}", serial()))?,
                    &*lease
                )
                .is_err()
        );
        assert_eq!(store.info()?.head, before);
    }
    let id = message()?;
    store.append(
        work(&f, id.clone(), vec![f.b.clone()], "private-work")?,
        &*lease,
    )?;
    let mut a = store.snapshot(f.self_scope(&f.a))?;
    assert!(a.message(id).is_err());
    assert_eq!(
        a.message_count(query(Some(Actor::Agent(f.a.clone())), true))?,
        0
    );
    a.close()?;
    store.close()?;
    Ok(())
}

#[test]
fn old_schema_mail_reads_and_direct_marks_remain_usable_until_host_migration() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let id = message()?;
    store.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            id.clone(),
            "legacy body",
            "legacy",
        )?,
        &*lease,
    )?;
    store.close()?;
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    db.execute_batch(
        "DROP TABLE work_mark_data; DROP TABLE message_deliveries; PRAGMA user_version=2",
    )?;
    drop(db);
    let mut store = present(SqliteFactory::open_direct(&f.options, &*lease)?)?;
    let mut s = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(
        s.messages(
            query(Some(Actor::Agent(f.b.clone())), true),
            budget(10, 65536, None)?
        )?
        .items()
        .len(),
        1
    );
    assert!(
        matches!(present(s.message(id.clone())?)?.body,StoredText::Present(body) if body=="legacy body")
    );
    s.close()?;
    let mark = f.batch(
        f.self_scope(&f.b).admission,
        None,
        vec![EventBody::MessageRead {
            message: id.clone(),
            recipient: Actor::Agent(f.b.clone()),
        }],
    )?;
    let receipt = store.append(mark, &*lease)?;
    let mut s = store.snapshot(f.self_scope(&f.b))?;
    assert!(present(s.message(id)?)?.read.is_some());
    assert!(matches!(
        present(s.event(receipt.primary_event)?)?.body,
        EventBody::MessageRead { .. }
    ));
    assert_eq!(
        s.message_count(query(Some(Actor::Agent(f.b.clone())), true))?,
        0
    );
    s.close()?;
    assert_eq!(store.info()?.schema_version, 2);
    store.close()?;
    Ok(())
}
