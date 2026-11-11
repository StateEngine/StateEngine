//! Native conversation/item identity survives a new engine session.
use se_store::*;
use se_types::SessionId;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(
    dead_code,
    reason = "Only the needed capture fixture constructors are shared here."
)]
#[path = "support/capture_fixture.rs"]
mod capture_fixture;
use capture_fixture::*;

fn bind(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    id: &SessionId,
    src: RecordId,
    conversation: &str,
) -> Check {
    bind_provider(f, d, lease, id, src, conversation, Provider::Codex)
}
fn bind_provider(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    id: &SessionId,
    src: RecordId,
    conversation: &str,
    backend: Provider,
) -> Check {
    let mut preparation = prepared(f, id, &f.a);
    if let EventBody::SessionPrepared {
        provider,
        native_ref,
        ..
    } = &mut preparation
    {
        *provider = backend;
        // CaptureSource pins the conversation independently of the engine session.
        *native_ref = conversation.into();
    }
    let mut binding = source(src, id, b"first", Expected::Absent);
    if let EventBody::CaptureSource { native_ref, .. } = &mut binding {
        *native_ref = conversation.into();
    }
    d.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("bind-{id}"))?),
            vec![preparation, activated(id)?, binding],
        )?,
        lease,
    )?;
    Ok(())
}
fn item(
    f: &Fixture,
    id: &SessionId,
    src: RecordId,
    n: u64,
    vendor: &str,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    item_provider(f, id, src, n, vendor, Provider::Codex)
}
fn item_provider(
    f: &Fixture,
    id: &SessionId,
    src: RecordId,
    n: u64,
    vendor: &str,
    backend: Provider,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut batch = capture(f, id, src, b"first", n * 10, n + 1, vendor)?;
    if let EventBody::SessionTurn { provider, .. } = &mut batch.events[0].body {
        *provider = backend;
    }
    Ok(batch)
}

#[test]
fn fresh_import_can_prepare_its_codex_session_and_capture_in_one_batch() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let session = session()?;
    let src = record()?;
    let mut setup = prepared(&f, &session, &f.a);
    if let EventBody::SessionPrepared {
        provider,
        native_ref,
        ..
    } = &mut setup
    {
        *provider = Provider::Codex;
        *native_ref = "imported-thread".into();
    }
    let mut binding = source(src, &session, b"first", Expected::Absent);
    if let EventBody::CaptureSource { native_ref, .. } = &mut binding {
        *native_ref = "imported-thread".into();
    }
    let mut bodies = vec![setup, activated(&session)?, binding];
    bodies.extend(
        item(&f, &session, src, 0, "imported-item")?
            .events
            .into_iter()
            .map(|event| event.body),
    );
    let mut batch = f.batch(f.owner_project(), Some(request("first-import")?), bodies)?;
    batch.admission.session = Some(session.clone());
    for event in &mut batch.events {
        event.header.session = Some(session.clone());
    }
    let receipt = d.append(batch, &*lease)?;
    let mut read = d.snapshot(f.self_scope(&f.a))?;
    let rows = read.turns(f.a.clone(), budget(10, 100_000, None)?)?;
    assert_eq!(rows.items().len(), 1);
    assert!(receipt.events.contains(&rows.items()[0].header.event));
    assert!(matches!(
        present(read.capture_source(src)?)?.current.body,
        EventBody::CaptureProgress { new_offset: 10, .. }
    ));
    Ok(())
}

#[test]
fn an_existing_session_with_unreadable_data_still_refuses_without_capture() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let session = session()?;
    let src = record()?;
    bind(&f, &mut d, &lease, &session, src, "damaged-thread")?;
    let head = d.info()?.head;
    let external = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    external.execute(
        "ALTER TABLE session_data RENAME TO retained_session_data",
        [],
    )?;
    let error = d
        .append(item(&f, &session, src, 0, "new-item")?, &*lease)
        .err()
        .ok_or("damaged session was accepted as a fresh session")?;
    assert_eq!(error.code, StoreErrorCode::Unreadable);
    assert_eq!(
        d.info()?.head,
        head,
        "unreadable session advanced the floor"
    );
    Ok(())
}

#[test]
fn resume_reuses_six_native_events_and_timestamps_but_appends_new_items() -> Check {
    resume_twice(Provider::Codex)
}
#[test]
fn claude_two_resumes_keep_nine_native_uuids_once() -> Check {
    resume_twice(Provider::Claude)
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn resume_twice(backend: Provider) -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let first = session()?;
    let resumed = session()?;
    let third = session()?;
    let first_src = record()?;
    let resumed_src = record()?;
    let third_src = record()?;
    bind_provider(
        &f,
        &mut d,
        &lease,
        &first,
        first_src,
        "native-thread",
        backend,
    )?;
    let mut originals = Vec::new();
    for n in 0..6 {
        let receipt = d.append(
            item_provider(&f, &first, first_src, n, &format!("turn-{n}"), backend)?,
            &*lease,
        )?;
        let mut snap = d.snapshot(f.self_scope(&f.a))?;
        originals.push(present(snap.event(receipt.primary_event)?)?);
    }
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("end-first")?),
            vec![EventBody::SessionEnded {
                session: first.clone(),
                expected: revision(2)?,
                reason: InputText::Inline("native stopped".into()),
                final_turn: None,
                final_cursor: None,
            }],
        )?,
        &*lease,
    )?;
    bind_provider(
        &f,
        &mut d,
        &lease,
        &resumed,
        resumed_src,
        "native-thread",
        backend,
    )?;
    let head = d.info()?.head;
    for change_role in [false, true] {
        let mut changed = item_provider(&f, &resumed, resumed_src, 0, "turn-0", backend)?;
        if let EventBody::SessionTurn { role, text, .. } = &mut changed.events[0].body {
            if change_role {
                *role = Role::User;
            } else {
                *text = InputText::Inline("conflicting native text".into());
            }
        }
        let error = d
            .append(changed, &*lease)
            .err()
            .ok_or("conflicting native identity was accepted")?;
        assert_eq!(error.code, StoreErrorCode::NaturalKeyConflict);
        assert_eq!(
            d.info()?.head,
            head,
            "conflict advanced floor or source cursor"
        );
    }
    for n in 0..6 {
        let replay = d.append(
            item_provider(&f, &resumed, resumed_src, n, &format!("turn-{n}"), backend)?,
            &*lease,
        )?;
        assert_eq!(replay.primary_event, originals[n as usize].header.event);
    }
    end(&f, &mut d, &lease, &resumed)?;
    bind_provider(
        &f,
        &mut d,
        &lease,
        &third,
        third_src,
        "native-thread",
        backend,
    )?;
    for n in 0..9 {
        let mut batch = item_provider(&f, &third, third_src, n, &format!("turn-{n}"), backend)?;
        for event in &mut batch.events {
            event.header.occurred_at_us = 1_800_000_000_000_000;
        }
        let receipt = d.append(batch, &*lease)?;
        if n < 6 {
            assert_eq!(
                receipt.primary_event, originals[n as usize].header.event,
                "B31-04: native replay created another event"
            );
        }
    }
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    let turns = snap.turns(f.a.clone(), budget(100, 100_000, None)?)?;
    assert_eq!(turns.items().len(), 9, "B31-04: history grew on replay");
    for old in originals {
        let retained = present(snap.event(old.header.event.clone())?)?;
        assert_eq!(retained.header.occurred_at_us, old.header.occurred_at_us);
        assert_eq!(retained.header.session, Some(first.clone()));
    }
    let cursor = present(snap.capture_source(third_src)?)?;
    assert!(matches!(
        cursor.current.body,
        EventBody::CaptureProgress { new_offset: 90, .. }
    ));
    snap.close()?;
    let head = d.info()?.head;
    let replay = d.append(
        item_provider(&f, &third, third_src, 8, "turn-8", backend)?,
        &*lease,
    )?;
    assert_eq!(replay.state, CommitState::NaturalKeyReplay);
    assert_eq!(d.info()?.head, head);
    Ok(())
}

fn end(f: &Fixture, d: &mut SqliteDirect, lease: &Lease, id: &SessionId) -> Check {
    d.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("end-{id}"))?),
            vec![EventBody::SessionEnded {
                session: id.clone(),
                expected: revision(2)?,
                reason: InputText::Inline("stopped".into()),
                final_turn: None,
                final_cursor: None,
            }],
        )?,
        lease,
    )?;
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn conflicting_native_facts_refuse_and_new_conversation_provider_or_agent_appends() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let a = session()?;
    let sa = record()?;
    bind(&f, &mut d, &lease, &a, sa, "thread-one")?;
    let original = d.append(item(&f, &a, sa, 0, "same-item")?, &*lease)?;
    end(&f, &mut d, &lease, &a)?;
    let b = session()?;
    let sb = record()?;
    bind(&f, &mut d, &lease, &b, sb, "thread-one")?;
    let head = d.info()?.head;
    for change_role in [false, true] {
        let mut changed = item(&f, &b, sb, 0, "same-item")?;
        if let EventBody::SessionTurn { role, text, .. } = &mut changed.events[0].body {
            if change_role {
                *role = Role::User;
            } else {
                *text = InputText::Inline("different native text".into());
            }
        }
        let error = d
            .append(changed, &*lease)
            .err()
            .ok_or("changed native item was accepted")?;
        assert_eq!(error.code, StoreErrorCode::NaturalKeyConflict);
        assert_eq!(d.info()?.head, head);
    }
    let retained = d.append(item(&f, &b, sb, 0, "same-item")?, &*lease)?;
    assert_eq!(retained.primary_event, original.primary_event);
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    let native = present(snap.native_turn(b.clone(), Provider::Codex, "same-item")?)?;
    assert_eq!(native.header.event, original.primary_event);
    assert!(matches!(
        present(snap.capture_source(sb)?)?.current.body,
        EventBody::CaptureProgress {
            replay_evidence: Some(_),
            ..
        }
    ));
    snap.close()?;
    end(&f, &mut d, &lease, &b)?;
    let c = session()?;
    let sc = record()?;
    bind(&f, &mut d, &lease, &c, sc, "thread-two")?;
    let different = d.append(item(&f, &c, sc, 0, "same-item")?, &*lease)?;
    assert_ne!(different.primary_event, original.primary_event);
    end(&f, &mut d, &lease, &c)?;
    let claude = session()?;
    let ss = record()?;
    active(&f, &mut d, &lease, &claude, ss)?;
    let other = d.append(
        capture(&f, &claude, ss, b"first", 0, 1, "same-item")?,
        &*lease,
    )?;
    assert_ne!(other.primary_event, original.primary_event);
    let other_session = session()?;
    let other_source = record()?;
    let mut prepared = prepared(&f, &other_session, &f.b);
    if let EventBody::SessionPrepared {
        provider,
        native_ref,
        ..
    } = &mut prepared
    {
        *provider = Provider::Codex;
        *native_ref = "thread-one".into();
    }
    let mut bound = source(other_source, &other_session, b"first", Expected::Absent);
    if let EventBody::CaptureSource { native_ref, .. } = &mut bound {
        *native_ref = "thread-one".into();
    }
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("other-agent")?),
            vec![prepared, activated(&other_session)?, bound],
        )?,
        &*lease,
    )?;
    let mut batch = item(&f, &other_session, other_source, 0, "same-item")?;
    batch.admission.actor = Actor::Agent(f.b.clone());
    for event in &mut batch.events {
        event.header.actor = Actor::Agent(f.b.clone());
    }
    if let EventBody::SessionTurn { agent, .. } = &mut batch.events[0].body {
        *agent = f.b.clone();
    }
    let other = d.append(batch, &*lease)?;
    assert_ne!(other.primary_event, original.primary_event);
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    assert!(
        snap.native_turn(other_session, Provider::Codex, "same-item")
            .is_err(),
        "native lookup crossed principal visibility"
    );
    assert_eq!(
        snap.turns(f.a.clone(), budget(100, 100_000, None)?)?
            .items()
            .len(),
        3
    );
    Ok(())
}
