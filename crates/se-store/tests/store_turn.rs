use se_store::*;
use se_types::Read;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/capture_fixture.rs"]
mod capture_fixture;
use capture_fixture::*;
fn captured(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
) -> Result<(RecordId, CommitReceipt), Box<dyn std::error::Error>> {
    let id = session()?;
    let source = record()?;
    active(f, d, lease, &id, source)?;
    let batch = capture(f, &id, source, b"first", 0, 1, "exact-turn")?;
    let EventBody::SessionTurn { turn, .. } = &batch.events[0].body else {
        return Err("fixture omitted turn".into());
    };
    let turn = *turn;
    let receipt = d.append(batch, lease)?;
    Ok((turn, receipt))
}

/// Protects: exact captured-turn lookup — a RecordId returns its original immutable event, complete body and source-range evidence after later unrelated events, never the latest turn or a list approximation.
#[test]
fn exact_turn_retains_original_event_and_source_evidence() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (turn, receipt) = captured(&f, &mut d, &lease)?;
    d.append(
        f.working("later unrelated head", Expected::Absent, "later-head")?,
        &*lease,
    )?;
    let mut read = d.snapshot(f.self_scope(&f.a))?;
    let event = present(read.turn(turn)?)?;
    assert_eq!(event.header.event, receipt.primary_event);
    assert_eq!(event.position, receipt.first);
    assert_eq!(event.header.actor, Actor::Agent(f.a.clone()));
    let EventBody::SessionTurn {
        turn: actual,
        text: StoredText::Present(text),
        vendor_ref,
        evidence,
        ..
    } = event.body
    else {
        return Err("exact lookup lost the original turn body".into());
    };
    assert_eq!(actual, turn);
    assert_eq!(text, "captured exact-turn");
    assert_eq!(vendor_ref, "exact-turn");
    assert_eq!(
        evidence
            .path
            .ok_or("file-backed turn lost its source path")?
            .to_local()?,
        f.home.join("transcript.jsonl")
    );
    assert_eq!(evidence.incarnation, b"first");
    assert_eq!((evidence.offset, evidence.length), (0, 10));
    assert_eq!(
        evidence.sha256,
        Some(<[u8; 32]>::from(sha2::Sha256::digest(b"ten bytes!")))
    );
    assert!(matches!(read.turn(record()?)?, Read::Absent { .. }));
    read.close()?;
    Ok(())
}
use sha2::Digest;

/// Protects: exact turn visibility — owner and the admitted agent may read a turn while another agent or project cannot turn a known RecordId into access to its text/evidence.
#[test]
fn exact_turn_obeys_project_and_principal_visibility() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (turn, _) = captured(&f, &mut d, &lease)?;
    let mut owner = d.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(owner.turn(turn)?, Read::Present { .. }));
    owner.close()?;
    let mut other = d.snapshot(f.self_scope(&f.b))?;
    let error = other
        .turn(turn)
        .err()
        .ok_or("foreign principal read an exact turn")?;
    assert_eq!(error.code, StoreErrorCode::ScopeMismatch);
    other.close()?;
    let project = se_types::ProjectId::from_parts(1_700_000_000_000 + serial(), [88; 10])?;
    let mut scoped = f.scoped(Visibility::Owner);
    scoped.admission.scope = Scope::Project(project);
    let mut other_project = d.snapshot(scoped)?;
    assert!(matches!(other_project.turn(turn)?, Read::Absent { .. }));
    other_project.close()?;
    Ok(())
}

/// Protects: exact turn snapshot semantics — a turn committed after an existing read snapshot stays absent there and becomes visible only in a fresh finite snapshot.
#[test]
fn exact_turn_does_not_escape_the_callers_snapshot() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut before = reader.snapshot(f.scoped(Visibility::Owner))?;
    let _ = before.info();
    let (turn, _) = captured(&f, &mut d, &lease)?;
    assert!(matches!(before.turn(turn)?, Read::Absent { .. }));
    before.close()?;
    let mut after = reader.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(after.turn(turn)?, Read::Present { .. }));
    after.close()?;
    Ok(())
}

/// Protects: exact turn corruption handling — an indexed turn whose immutable event kind/body is corrupt refuses instead of being returned as an absent or unrelated event.
#[test]
fn corrupted_immutable_turn_refuses_without_absence_substitution() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (turn, receipt) = captured(&f, &mut d, &lease)?;
    let database = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    let id = receipt
        .primary_event
        .canonical_bytes()?
        .ok_or("canonical event")?;
    // Explicit corruption fixture in this test's private database. Remove only
    // the immutable-header update trigger so the real decoder sees damage a
    // normal store append cannot produce; no product source/guard is changed.
    let triggers: Vec<String> = database.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events' AND upper(sql) LIKE '%BEFORE UPDATE%'")?.query_map([], |row|row.get(0))?.collect::<Result<_,_>>()?;
    assert_eq!(triggers.len(), 1, "immutable event trigger fixture drifted");
    let name = &triggers[0];
    assert!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    database.execute_batch(&format!("DROP TRIGGER {name}"))?;
    assert_eq!(
        database.execute(
            "UPDATE events SET kind='message.sent' WHERE event_id=?",
            [id.as_slice()]
        )?,
        1
    );
    drop(database);
    let mut read = d.snapshot(f.scoped(Visibility::Owner))?;
    let error = read
        .turn(turn)
        .err()
        .ok_or("corrupt immutable turn became success or absence")?;
    assert!(matches!(
        error.code,
        StoreErrorCode::ProjectionInconsistent | StoreErrorCode::Unreadable
    ));
    read.close()?;
    Ok(())
}
