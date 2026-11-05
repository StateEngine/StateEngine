//! An explicit agent selector includes received mail and intersects caller visibility.
use se_store::*;
use se_types::{AgentId, EventId, WorkAction, WorkAddressing};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn selected(agent: &AgentId) -> HistoryQuery {
    HistoryQuery {
        agent: Some(agent.clone()),
        session: None,
        kinds: vec![],
        families: vec![HistoryFamily::Messages],
        transcript: TranscriptFilter::All,
        since: None,
    }
}

fn check_reads(
    store: &mut SqliteDirect,
    scope: ReadScope,
    agent: &AgentId,
    expected: &[EventId],
) -> Check {
    let mut snapshot = store.snapshot(scope)?;
    let mut history_ids = Vec::new();
    let mut cursor = None;
    for _ in 0..10 {
        let page = snapshot.history(selected(agent), budget(1, 65536, cursor)?)?;
        history_ids.extend(page.items().iter().map(|event| event.header.event.clone()));
        cursor = page.next().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert!(
        cursor.is_none(),
        "agent history did not exhaust its bounded fixture"
    );
    assert_eq!(
        history_ids, expected,
        "agent history must include received mail exactly once, without private rows"
    );
    let mut search_ids = Vec::new();
    let mut cursor = None;
    for _ in 0..10 {
        let page = snapshot.search(
            SearchQuery {
                text: "recipient-probe".into(),
                history: selected(agent),
            },
            budget(1, 65536, cursor)?,
        )?;
        search_ids.extend(page.items().iter().map(|hit| hit.event.clone()));
        cursor = page.next().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert!(
        cursor.is_none(),
        "agent search did not exhaust its bounded fixture"
    );
    assert_eq!(
        search_ids, expected,
        "search must share the agent/visibility intersection"
    );
    snapshot.close()?;
    Ok(())
}

fn direct_mail(legacy: bool) -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let mut events = Vec::new();
    for (sender, recipient, label) in [
        (
            Actor::Agent(f.b.clone()),
            Actor::Agent(f.a.clone()),
            "received",
        ),
        (Actor::Agent(f.a.clone()), Actor::Agent(f.b.clone()), "sent"),
        (
            Actor::Human(f.owner.clone()),
            Actor::Agent(f.b.clone()),
            "private-b",
        ),
        (
            Actor::Human(f.owner.clone()),
            Actor::Agent(f.a.clone()),
            "private-a",
        ),
    ] {
        events.push(
            store
                .append(
                    f.send(
                        sender,
                        recipient,
                        message()?,
                        &format!("recipient-probe {label}"),
                        label,
                    )?,
                    &*lease,
                )?
                .primary_event,
        );
    }
    if legacy {
        store.close()?;
        let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
        db.execute_batch(
            "DROP TABLE work_mark_data; DROP TABLE message_deliveries; PRAGMA user_version=2",
        )?;
        drop(db);
        store = present(SqliteFactory::open_direct(&f.options, &*lease)?)?;
        assert_eq!(store.info()?.schema_version, 2);
    }
    for scope in [f.scoped(Visibility::Owner), f.self_scope(&f.a)] {
        check_reads(
            &mut store,
            scope,
            &f.a,
            &[events[0].clone(), events[1].clone(), events[3].clone()],
        )?;
    }
    // Selecting A does not authorize B to read the owner's private message to A.
    check_reads(&mut store, f.self_scope(&f.b), &f.a, &events[..2])?;
    // Selecting B similarly keeps the owner's private message to B hidden from A.
    check_reads(&mut store, f.self_scope(&f.a), &f.b, &events[..2])?;
    check_reads(&mut store, f.scoped(Visibility::Owner), &f.b, &events[..3])?;
    store.close()?;
    Ok(())
}

#[test]
fn current_schema_agent_history_and_search_include_received_direct_mail() -> Check {
    direct_mail(false)
}

#[test]
fn retained_schema_agent_history_and_search_include_received_direct_mail() -> Check {
    direct_mail(true)
}

#[test]
fn work_fanout_is_one_history_event_and_never_expands_caller_visibility() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let mut events = Vec::new();
    for (label, addressees) in [
        ("shared", vec![f.a.clone(), f.b.clone()]),
        ("private-a", vec![f.a.clone()]),
        ("private-b", vec![f.b.clone()]),
    ] {
        events.push(
            store
                .append(
                    f.batch(
                        f.owner_project(),
                        Some(request(label)?),
                        vec![EventBody::WorkMessageSent {
                            quiet: false,
                            message: message()?,
                            work: WorkAddressing {
                                action: WorkAction::Finding,
                                addressees,
                            },
                            kind: "finding".into(),
                            body: InputText::Inline(format!("recipient-probe {label}")),
                            refs: vec![],
                            reply_to: None,
                        }],
                    )?,
                    &*lease,
                )?
                .primary_event,
        );
    }
    check_reads(&mut store, f.scoped(Visibility::Owner), &f.a, &events[..2])?;
    check_reads(&mut store, f.self_scope(&f.a), &f.a, &events[..2])?;
    check_reads(&mut store, f.self_scope(&f.b), &f.a, &events[..1])?;
    check_reads(&mut store, f.self_scope(&f.a), &f.b, &events[..1])?;
    check_reads(
        &mut store,
        f.scoped(Visibility::Owner),
        &f.b,
        &[events[0].clone(), events[2].clone()],
    )?;
    store.close()?;
    Ok(())
}
