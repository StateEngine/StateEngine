//! Independent consumer of bounded search across retained content loss.
use se_store::*;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
fn query() -> SearchQuery {
    SearchQuery {
        text: "nEeDlE".into(),
        history: HistoryQuery {
            agent: None,
            session: None,
            kinds: vec![EventKind::MessageSent],
            families: vec![],
            transcript: TranscriptFilter::All,
            since: None,
        },
    }
}
#[test]
fn lost_candidates_advance_across_snapshots_without_leaking_later_appends() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    let mut seqs = Vec::new();
    for (index, text) in [
        "forgotten needle",
        "broken needle one",
        "broken needle two",
        "visible NEEDLE 🦀",
    ]
    .into_iter()
    .enumerate()
    {
        writer.append(
            f.send(
                Actor::Agent(f.a.clone()),
                Actor::Agent(f.b.clone()),
                message()?,
                text,
                &format!("judge-loss-{index}"),
            )?,
            &*lease,
        )?;
        seqs.push(db.query_row("SELECT max(seq) FROM events", [], |r| r.get::<_, i64>(0))?);
    }
    db.execute("INSERT INTO erasures(erasure_id,requested_seq,manifest_payload) SELECT zeroblob(16),?1,payload_id FROM payloads WHERE event_seq=?1 AND field='body'", [seqs[0]])?;
    db.execute("INSERT INTO erased_fields(event_seq,field,original_bytes,erasure_id) VALUES(?1,'body',16,zeroblob(16))", [seqs[0]])?;
    db.execute_batch("DROP TRIGGER payloads_no_update")?;
    for seq in &seqs[1..3] {
        db.execute(
            "UPDATE payloads SET sha256=zeroblob(32) WHERE event_seq=?",
            [seq],
        )?;
    }
    let mut snap = writer.snapshot(f.self_scope(&f.b))?;
    let first = snap.search(query(), budget(2, 65536, None)?)?;
    assert!(first.items().is_empty());
    assert_eq!(first.erased, 1);
    assert_eq!(first.window().fields().ok_or("window")?.unreadable, 1);
    assert!(!first.window().complete());
    let cursor = first
        .next()
        .cloned()
        .ok_or("lost-row page stranded its continuation")?;
    snap.close()?;
    writer.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            message()?,
            "late NEEDLE must stay outside original window",
            "judge-late",
        )?,
        &*lease,
    )?;
    let mut snap = writer.snapshot(f.self_scope(&f.b))?;
    let second = snap.search(query(), budget(2, 65536, Some(cursor))?)?;
    assert_eq!(second.erased, 0);
    assert_eq!(second.window().fields().ok_or("window")?.unreadable, 1);
    assert_eq!(
        second.items().len(),
        1,
        "lost candidates or a later append changed the original search"
    );
    assert!(
        matches!(&second.items()[0].snippet, StoredText::Present(text) if text == "visible NEEDLE 🦀")
    );
    assert!(
        second.next().is_none(),
        "fixed-H exhaustion invented a continuation"
    );
    assert!(
        !second.window().complete(),
        "unreadable content became complete absence"
    );
    let fresh = snap.search(query(), budget(10, 65536, None)?)?;
    assert_eq!(fresh.items().len(), 2);
    assert_eq!(fresh.erased, 1);
    assert_eq!(fresh.window().fields().ok_or("window")?.unreadable, 2);
    assert!(fresh.next().is_none());
    assert!(!fresh.window().complete());
    snap.close()?;
    Ok(())
}
