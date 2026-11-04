use se_store::*;
use se_types::{Cursor, StopReason};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(
    dead_code,
    reason = "Shared capture helpers also contain keyless setup; this fixture prepares with explicit request identities."
)]
#[path = "support/capture_fixture.rs"]
mod capture_fixture;
use capture_fixture::*;

fn history() -> HistoryQuery {
    HistoryQuery {
        agent: None,
        session: None,
        kinds: vec![],
        families: vec![],
        transcript: TranscriptFilter::All,
        since: None,
    }
}
fn search(text: &str) -> SearchQuery {
    let mut history = history();
    history.kinds = vec![EventKind::MessageSent];
    SearchQuery {
        text: text.into(),
        history,
    }
}

#[test]
fn shared_work_history_and_search_include_only_the_admitted_recipient() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("work-history")?),
            vec![EventBody::WorkMessageSent {
                quiet: false,
                message: message()?,
                work: se_types::WorkAddressing {
                    action: se_types::WorkAction::Finding,
                    addressees: vec![f.a.clone()],
                },
                kind: "finding".into(),
                body: InputText::Inline("cutover searchable text".into()),
                refs: vec![],
                reply_to: None,
            }],
        )?,
        &*lease,
    )?;
    let mut query = history();
    query.kinds = vec![EventKind::WorkMessageSent];
    for (agent, expected) in [(&f.a, 1), (&f.b, 0)] {
        let mut snap = d.snapshot(f.self_scope(agent))?;
        assert_eq!(
            snap.history(query.clone(), budget(10, 65536, None)?)?
                .items()
                .len(),
            expected
        );
        assert_eq!(
            snap.search(
                SearchQuery {
                    text: "searchable".into(),
                    history: query.clone()
                },
                budget(10, 65536, None)?
            )?
            .items()
            .len(),
            expected
        );
        assert_eq!(snap.message_count(query_mail(agent))?, expected as u64);
        snap.close()?;
    }
    Ok(())
}

fn query_mail(agent: &se_types::AgentId) -> MessageQuery {
    fixture::query(Some(Actor::Agent(agent.clone())), true)
}

#[test]
fn search_advances_nonmatches_and_binds_scope_query_and_original_high_water() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    for (index, text) in ["first nonmatch", "İstanbul TARGET café", "third nonmatch"]
        .iter()
        .enumerate()
    {
        d.append(
            f.send(
                Actor::Agent(f.a.clone()),
                Actor::Agent(f.b.clone()),
                message()?,
                text,
                &format!("search-{index}"),
            )?,
            &*lease,
        )?;
    }
    let mut snap = d.snapshot(f.self_scope(&f.b))?;
    let first = snap.search(search("target"), budget(1, 65536, None)?)?;
    assert!(first.items().is_empty());
    assert_eq!(
        first.window().fields().ok_or("missing window")?.stop_reason,
        StopReason::ItemLimit
    );
    let cursor = first.next().cloned().ok_or("nonmatch lost continuation")?;
    assert!(cursor.as_str().len() <= 192);
    snap.close()?;
    d.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            message()?,
            "new TARGET",
            "search-new",
        )?,
        &*lease,
    )?;
    let mut snap = d.snapshot(f.self_scope(&f.b))?;
    let second = snap.search(search("target"), budget(1, 65536, Some(cursor.clone()))?)?;
    let hit = second.items().first().ok_or("match omitted")?;
    assert!(matches!(&hit.snippet, StoredText::Present(s) if s == "İstanbul TARGET café"));
    assert!(hit.body_complete);
    let third = snap.search(search("target"), budget(1, 65536, second.next().cloned())?)?;
    assert!(third.items().is_empty());
    assert!(
        third.next().is_none(),
        "new event escaped original high water"
    );
    assert_eq!(
        snap.search(search("other"), budget(1, 65536, Some(cursor.clone()))?)
            .err()
            .ok_or("query changed")?
            .code,
        StoreErrorCode::CursorInvalid
    );
    snap.close()?;
    let mut owner = d.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        owner
            .search(search("target"), budget(1, 65536, Some(cursor))?)
            .err()
            .ok_or("principal changed")?
            .code,
        StoreErrorCode::CursorInvalid
    );
    owner.close()?;
    Ok(())
}

#[test]
fn search_refuses_tiny_budgets_and_deadlines_without_claiming_absence() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    d.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            message()?,
            "needle",
            "search-budget",
        )?,
        &*lease,
    )?;
    let mut snap = d.snapshot(f.self_scope(&f.b))?;
    let error = snap
        .search(search("needle"), budget(10, 1, None)?)
        .err()
        .ok_or("tiny budget became empty search")?;
    assert_eq!(error.code, StoreErrorCode::ReadBudgetTooSmall);
    assert!(matches!(error.detail, StoreDetail::Budget { required: Some(n), .. } if n > 1));
    let mut tiny = budget(10, 65536, None)?;
    tiny.deadline = std::time::Duration::from_nanos(1);
    assert_eq!(
        snap.search(search("needle"), tiny)
            .err()
            .ok_or("expired deadline succeeded")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    let mut excessive = budget(10, 65536, None)?;
    excessive.deadline = std::time::Duration::from_secs(6);
    assert_eq!(
        snap.search(search("needle"), excessive)
            .err()
            .ok_or("invalid deadline accepted")?
            .code,
        StoreErrorCode::EventInvalid
    );
    snap.close()?;
    Ok(())
}

#[test]
fn search_continues_across_erased_and_unreadable_candidates_but_refuses_a_broken_store() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    let mut seqs = Vec::new();
    for (index, text) in ["forgotten needle", "corrupt needle", "later needle"]
        .iter()
        .enumerate()
    {
        d.append(
            f.send(
                Actor::Agent(f.a.clone()),
                Actor::Agent(f.b.clone()),
                message()?,
                text,
                &format!("loss-{index}"),
            )?,
            &*lease,
        )?;
        seqs.push(db.query_row("SELECT max(seq) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })?);
    }
    // Retained erasure metadata must suppress even a residual old body copy.
    // The erasure operation itself belongs to its separate maintenance lane.
    db.execute("INSERT INTO erasures(erasure_id,requested_seq,manifest_payload) SELECT zeroblob(16),?1,payload_id FROM payloads WHERE event_seq=?1 AND field='body'", [seqs[0]])?;
    db.execute("INSERT INTO erased_fields(event_seq,field,original_bytes,erasure_id) VALUES(?1,'body',16,zeroblob(16))", [seqs[0]])?;
    db.execute_batch("DROP TRIGGER payloads_no_update")?;
    db.execute(
        "UPDATE payloads SET sha256=zeroblob(32) WHERE event_seq=?",
        [seqs[1]],
    )?;
    let mut snap = d.snapshot(f.self_scope(&f.b))?;
    let erased = snap.search(search("needle"), budget(1, 65536, None)?)?;
    assert_eq!(erased.erased, 1, "erased candidate was not counted");
    assert!(erased.items().is_empty(), "forgotten text resurfaced");
    let unreadable = snap.search(search("needle"), budget(1, 65536, erased.next().cloned())?)?;
    assert_eq!(unreadable.erased, 0);
    assert!(unreadable.items().is_empty());
    assert_eq!(
        unreadable
            .window()
            .fields()
            .ok_or("missing accounting")?
            .unreadable,
        1
    );
    assert_eq!(
        unreadable.window().omitted().reason,
        Some(se_types::OmissionReason::Unreadable)
    );
    assert!(!unreadable.window().complete());
    let later = snap.search(
        search("needle"),
        budget(1, 65536, unreadable.next().cloned())?,
    )?;
    assert_eq!(
        later.items().len(),
        1,
        "later match was stranded behind unreadable content"
    );
    assert!(later.window().complete());
    assert!(later.next().is_none());
    let all = snap.search(search("needle"), budget(10, 65536, None)?)?;
    assert_eq!(all.erased, 1);
    assert_eq!(all.items().len(), 1);
    assert_eq!(all.window().omitted().count, Some(1));
    assert_eq!(
        all.window().omitted().reason,
        Some(se_types::OmissionReason::Unreadable)
    );
    assert!(!all.window().complete());
    assert!(
        all.next().is_none(),
        "exhausted unreadability invented more candidates"
    );
    snap.close()?;
    db.execute_batch("ALTER TABLE payloads RENAME TO broken_payloads")?;
    let mut snap = d.snapshot(f.self_scope(&f.b))?;
    assert!(
        snap.search(search("needle"), budget(10, 65536, None)?)
            .is_err(),
        "broken storage became per-row omissions"
    );
    snap.close()?;
    Ok(())
}

fn prepare(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
) -> Result<(se_types::SessionId, RecordId), Box<dyn std::error::Error>> {
    let id = session()?;
    let source_id = record()?;
    std::fs::write(f.home.join("transcript.jsonl"), b"ten bytes!ten bytes!")?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("read-window-session")?),
            vec![
                prepared(f, &id, &f.a),
                activated(&id)?,
                source(source_id, &id, b"first", Expected::Absent),
            ],
        )?,
        lease,
    )?;
    Ok((id, source_id))
}

#[test]
fn first_complete_head_and_turn_pages_report_the_required_minimum() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (session, source) = prepare(&f, &mut d, &lease)?;
    d.append(
        capture(&f, &session, source, b"first", 0, 1, "budget-turn")?,
        &*lease,
    )?;
    let mut snap = d.snapshot(f.scoped(Visibility::Owner))?;
    let check = |error: Option<Box<StoreError>>| -> Check {
        let error = error.ok_or("first full item became an empty page")?;
        assert_eq!(error.code, StoreErrorCode::ReadBudgetTooSmall);
        assert!(
            matches!(error.detail, StoreDetail::Budget { allowed: 1, required: Some(n) } if n > 1)
        );
        Ok(())
    };
    check(snap.principals(budget(10, 1, None)?).err())?;
    check(snap.sessions(budget(10, 1, None)?).err())?;
    check(snap.turns(f.a.clone(), budget(10, 1, None)?).err())?;
    check(
        snap.recent_turns(f.a.clone(), None, budget(10, 1, None)?)
            .err(),
    )?;
    snap.close()?;
    Ok(())
}

#[test]
fn exact_session_turn_history_uses_the_scoped_index_and_rejects_broken_joins() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (id, source_id) = prepare(&f, &mut d, &lease)?;
    let receipt = d.append(
        capture(&f, &id, source_id, b"first", 0, 1, "indexed-turn")?,
        &*lease,
    )?;
    let mut query = history();
    query.session = Some(id.clone());
    query.kinds = vec![EventKind::SessionTurn, EventKind::SessionTurn];
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    let page = snap.history(query.clone(), budget(1, 65536, None)?)?;
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].header.event, receipt.primary_event);
    snap.close()?;
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    let plan: Vec<String> = db.prepare("EXPLAIN QUERY PLAN SELECT e.seq FROM turn_data t INDEXED BY turn_data_session_seq JOIN events e ON e.seq=t.event_seq WHERE t.project_id=? AND t.session_id=? AND t.event_seq>? AND t.event_seq<=? ORDER BY t.event_seq LIMIT ?")?
        .query_map(rusqlite::params![f.project.canonical_bytes()?.ok_or("project")?.as_slice(),id.canonical_bytes()?.ok_or("session")?.as_slice(),0,i64::MAX,2], |r|r.get(3))?.collect::<Result<_,_>>()?;
    assert!(
        plan.iter()
            .any(|s| s.contains("SEARCH t USING") && s.contains("turn_data_session_seq"))
    );
    assert!(
        !plan
            .iter()
            .any(|s| s.contains("TEMP B-TREE") || s.contains("SCAN e"))
    );
    let unrelated = d.append(
        f.working("unrelated", Expected::Absent, "broken-join")?,
        &*lease,
    )?;
    // Private fixture corruption: the projection points at an existing wrong kind.
    db.execute_batch("DROP TRIGGER turn_data_no_update")?;
    db.execute(
        "UPDATE turn_data SET event_seq=? WHERE event_seq=?",
        rusqlite::params![
            event_sequence(&db, &unrelated.primary_event)?,
            event_sequence(&db, &receipt.primary_event)?
        ],
    )?;
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    let error = snap
        .history(query, budget(10, 65536, None)?)
        .err()
        .ok_or("broken turn join became exhaustion")?;
    assert_eq!(error.code, StoreErrorCode::ProjectionInconsistent);
    snap.close()?;
    Ok(())
}

fn import_batch(
    f: &Fixture,
    bodies: Vec<EventBody<InputText>>,
    checkpoint: Option<ImportCheckpoint>,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut batch = f.batch(
        f.owner_project(),
        Some(request(&format!("import-{}", serial()))?),
        bodies,
    )?;
    for event in &mut batch.events {
        event.header.door = Door::Import;
    }
    batch.import_checkpoint = checkpoint;
    Ok(batch)
}
fn progress(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    id: RecordId,
    source: (ImportFamily, &[u8]),
    expected: Expected,
    offset: u64,
) -> Check {
    let (family, source) = source;
    let checkpoint = ImportCheckpoint {
        import: id,
        family,
        source_key: source.into(),
        source_sha256: [1; 32],
        byte_offset: offset,
        row_offset: offset,
        expected,
    };
    d.append(
        import_batch(
            f,
            vec![EventBody::ImportProgress {
                checkpoint: checkpoint.clone(),
                counts: ImportCounts::default(),
            }],
            Some(checkpoint),
        )?,
        lease,
    )?;
    Ok(())
}

#[test]
fn import_progress_pages_by_source_key_even_when_earlier_heads_are_updated() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let id = record()?;
    d.append(
        import_batch(
            &f,
            vec![EventBody::ImportStarted {
                import: id,
                source: se_types::NativePath::from_local(f.home.join("source"))?,
                source_sha256: [1; 32],
                format: "test".into(),
                policy_version: 1,
            }],
            None,
        )?,
        &*lease,
    )?;
    for (family, key) in [
        (ImportFamily::Turns, b"z".as_slice()),
        (ImportFamily::Agents, b"b"),
        (ImportFamily::Agents, b"a"),
    ] {
        progress(&f, &mut d, &lease, id, (family, key), Expected::Absent, 0)?;
    }
    let mut snap = d.snapshot(f.scoped(Visibility::Owner))?;
    let first = snap.import_progress(id, budget(1, 65536, None)?)?;
    assert_eq!(first.items()[0].source_key, b"a");
    let cursor = first.next().cloned().ok_or("import continuation")?;
    snap.close()?;
    progress(
        &f,
        &mut d,
        &lease,
        id,
        (ImportFamily::Agents, b"a"),
        revision(1)?,
        1,
    )?;
    let mut snap = d.snapshot(f.scoped(Visibility::Owner))?;
    let second = snap.import_progress(id, budget(1, 65536, Some(cursor))?)?;
    assert_eq!(second.items()[0].source_key, b"b");
    let third = snap.import_progress(id, budget(1, 65536, second.next().cloned())?)?;
    assert_eq!(third.items()[0].source_key, b"z");
    assert!(third.next().is_none());
    let bad = Cursor::new("malformed")?;
    assert_eq!(
        snap.import_progress(id, budget(1, 65536, Some(bad))?)
            .err()
            .ok_or("bad cursor accepted")?
            .code,
        StoreErrorCode::CursorInvalid
    );
    snap.close()?;
    Ok(())
}

fn event_sequence(
    db: &rusqlite::Connection,
    event: &se_types::EventId,
) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(db.query_row(
        "SELECT seq FROM events WHERE event_id=?",
        [event.canonical_bytes()?.ok_or("event key")?.as_slice()],
        |r| r.get(0),
    )?)
}
