use se_store::*;
use se_types::Read;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

/// Bug: 2b61346 — keyed retries returned Committed instead of Replayed.
#[test]
fn direct_lost_ack_retains_original_receipt_after_a_later_head() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let original = store.append(f.working("first", Expected::Absent, "lost-ack")?, &*lease)?;
    assert_eq!(original.state, CommitState::Committed);
    store.append(f.working("second", revision(1)?, "later")?, &*lease)?;
    let head = store.info()?.head;
    // The new event ID and stale Absent head cannot invalidate a retained key.
    let replay = store.append(f.working("first", Expected::Absent, "lost-ack")?, &*lease)?;
    same_receipt(&original, &replay);
    assert_eq!(replay.state, CommitState::Replayed);
    assert_eq!(head, store.info()?.head);
    let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
    let retained =
        present(snapshot.operation_receipt(Actor::Agent(f.a.clone()), request("lost-ack")?.key)?)?;
    same_receipt(&original, &retained);
    assert_eq!(retained.state, CommitState::Committed);
    let changed = store.append(
        f.working("different", revision(2)?, "lost-ack")
            .map(|mut b| {
                if let Some(r) = b.request.as_mut() {
                    r.intent.sha256 = [7; 32];
                }
                b
            })?,
        &*lease,
    );
    assert_eq!(
        changed.err().ok_or("conflicting key accepted")?.code,
        StoreErrorCode::IdempotencyKeyReused
    );
    snapshot.close()?;
    store.close()?;
    Ok(())
}

/// Bug: 2b61346 — natural marker retries returned Committed instead of NaturalKeyReplay.
#[test]
fn marker_replay_keeps_one_event_and_current_unread_count() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let id = message()?;
    store.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            id.clone(),
            "mail",
            "mail",
        )?,
        &*lease,
    )?;
    let make = || {
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.b.clone())),
            None,
            vec![EventBody::MessageRead {
                message: id.clone(),
                recipient: Actor::Agent(f.b.clone()),
            }],
        )
    };
    let first = store.append(make()?, &*lease)?;
    let head = store.info()?.head;
    let again = store.append(make()?, &*lease)?;
    same_receipt(&first, &again);
    assert_eq!(again.state, CommitState::NaturalKeyReplay);
    assert_eq!(head, store.info()?.head);
    let mut s = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(
        s.message_count(query(Some(Actor::Agent(f.b.clone())), true))?,
        0
    );
    assert_eq!(
        present(s.resume_head(Actor::Agent(f.b.clone()))?)?.unread,
        0
    );
    s.close()?;
    store.close()?;
    Ok(())
}

/// Protects: S03 — one failing batch rolls back all its events and projection changes.
#[test]
fn atomic_batch_conflict_leaves_no_partial_projection() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let head = store.info()?.head;
    let b = f.batch(
        f.owner_project(),
        Some(request("atomic")?),
        vec![
            EventBody::WorkingStateSet {
                agent: f.a.clone(),
                text: InputText::Inline("rolled back".into()),
                expected: Expected::Absent,
            },
            EventBody::WorkingStateSet {
                agent: f.b.clone(),
                text: InputText::Inline("conflict".into()),
                expected: revision(99)?,
            },
        ],
    )?;
    assert_eq!(
        store
            .append(b, &*lease)
            .err()
            .ok_or("invalid CAS accepted")?
            .code,
        StoreErrorCode::RevisionConflict
    );
    assert_eq!(head, store.info()?.head);
    let mut s = store.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(s.working_state(f.a.clone())?, Read::Absent { .. }));
    s.close()?;
    let committed = store.append(
        f.working("after rollback", Expected::Absent, "after")?,
        &*lease,
    )?;
    assert_eq!(committed.state, CommitState::Committed);
    store.close()?;
    Ok(())
}

/// Protects: S04/S06 — mail pages and counts share one finite snapshot while fresh reads see markers.
#[test]
fn mail_count_and_pages_are_snapshot_consistent_and_visibility_bound() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let one = message()?;
    let two = message()?;
    for (id, sender, recipient) in [
        (one.clone(), f.a.clone(), f.b.clone()),
        (two, f.b.clone(), f.b.clone()),
        (message()?, f.b.clone(), f.a.clone()),
    ] {
        let key = format!("mail-{id}");
        store.append(
            f.send(
                Actor::Agent(sender),
                Actor::Agent(recipient),
                id,
                "body",
                &key,
            )?,
            &*lease,
        )?;
    }
    let q = query(Some(Actor::Agent(f.b.clone())), true);
    let mut old = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(old.message_count(q.clone())?, 2);
    let old_head = old.info().head;
    store.append(
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.b.clone())),
            None,
            vec![EventBody::MessageRead {
                message: one,
                recipient: Actor::Agent(f.b.clone()),
            }],
        )?,
        &*lease,
    )?;
    assert_eq!(old.message_count(q.clone())?, 2);
    assert_eq!(old.info().head, old_head);
    assert_eq!(
        old.messages(q.clone(), budget(20, 32768, None)?)?
            .items()
            .len(),
        2
    );
    old.close()?;
    let mut new = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(new.message_count(q.clone())?, 1);
    assert_eq!(new.messages(q, budget(20, 32768, None)?)?.items().len(), 1);
    // Both sent and received includes a self-message once.
    assert_eq!(new.message_count(query(None, false))?, 3);
    assert_eq!(
        new.messages(query(None, false), budget(20, 32768, None)?)?
            .items()
            .len(),
        3
    );
    new.close()?;
    store.close()?;
    Ok(())
}

/// Protects: S06 — quiescent keyset traversal has no gaps, and cursors bind principal/filter/budget.
#[test]
fn bounded_mail_traversal_and_cursor_refusals() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let mut expected = Vec::new();
    for n in 0..7 {
        let id = message()?;
        expected.push(id.clone());
        store.append(
            f.send(
                Actor::Agent(f.a.clone()),
                Actor::Agent(f.b.clone()),
                id,
                &"x".repeat(2000),
                &format!("page-{n}"),
            )?,
            &*lease,
        )?;
    }
    let mut s = store.snapshot(f.self_scope(&f.b))?;
    let q = query(Some(Actor::Agent(f.b.clone())), false);
    assert_eq!(s.message_count(q.clone())?, 7);
    let first = s.messages(q.clone(), budget(2, 32768, None)?)?;
    let cursor = first.next().ok_or("missing continuation")?.clone();
    let mut got: Vec<_> = first.items().iter().map(|m| m.message.clone()).collect();
    let mut after = Some(cursor.clone());
    while let Some(c) = after {
        let page = s.messages(q.clone(), budget(2, 32768, Some(c))?)?;
        got.extend(page.items().iter().map(|m| m.message.clone()));
        after = page.next().cloned();
    }
    assert_eq!(got, expected);
    let mut wrong = q.clone();
    wrong.unread_only = true;
    assert_eq!(
        s.messages(wrong, budget(2, 32768, Some(cursor.clone()))?)
            .err()
            .ok_or("filter cursor accepted")?
            .code,
        StoreErrorCode::CursorInvalid
    );
    assert_eq!(
        s.messages(q, budget(2, 64, None)?)
            .err()
            .ok_or("tiny budget silently truncated")?
            .code,
        StoreErrorCode::ReadBudgetTooSmall
    );
    s.close()?;
    let mut other = store.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        other
            .messages(
                query(Some(Actor::Agent(f.b.clone())), false),
                budget(2, 32768, Some(cursor))?
            )
            .err()
            .ok_or("other principal cursor accepted")?
            .code,
        StoreErrorCode::CursorInvalid
    );
    other.close()?;
    store.close()?;
    Ok(())
}

/// Protects: S01 — missing and corrupt stores remain distinct, and read/open never initialize either.
#[test]
fn missing_and_corrupt_state_are_not_empty_success() -> Check {
    let f = Fixture::new()?;
    let lease = Lease::acquire(&f.options.state_directory, LeaseMode::DirectClient, None)?;
    assert!(matches!(
        SqliteFactory::open_reader(&f.options)?,
        Read::Absent { .. }
    ));
    assert!(matches!(
        SqliteFactory::open_direct(&f.options, &*lease)?,
        Read::Absent { .. }
    ));
    assert!(!f.options.state_directory.join("state.db").try_exists()?);
    let mut stage = lease.files.0.create_staging(&f.options.state_directory)?;
    use std::io::Write;
    stage.file.write_all(b"broken database")?;
    drop(stage.file);
    let path = f.options.state_directory.join("state.db");
    lease.files.0.publish_no_replace(&stage.path, &path)?;
    assert_eq!(
        SqliteFactory::open_reader(&f.options)
            .err()
            .ok_or("corruption became absence")?
            .code,
        StoreErrorCode::Corrupt
    );
    assert_eq!(
        SqliteFactory::open_direct(&f.options, &*lease)
            .err()
            .ok_or("corruption became absence")?
            .code,
        StoreErrorCode::Corrupt
    );
    assert_eq!(std::fs::read(path)?, b"broken database");
    Ok(())
}

/// Protects: S01/S04 — published SQLite uses 4 KiB pages, immutable events and protected native side files.
#[test]
fn real_database_readback_and_missing_projection_refuse_honestly() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let id = message()?;
    let receipt = store.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            id,
            "persisted bytes",
            "readback",
        )?,
        &*lease,
    )?;
    assert_eq!(receipt.writer.kind(), WriterKind::Direct);
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    assert_eq!(
        db.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))?,
        4096
    );
    assert_eq!(
        db.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))?,
        "wal"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE kind='message.sent'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert!(
        db.execute("DELETE FROM events WHERE kind='message.sent'", [])
            .is_err()
    );
    for suffix in ["state.db", "state.db-wal", "state.db-shm"] {
        let path = f.options.state_directory.join(suffix);
        assert!(path.try_exists()?, "missing actual SQLite file {suffix}");
        let observed = lease.files.0.readback(&path);
        #[cfg(windows)]
        if let Err(error) = observed {
            for name in ["", "state.db", "state.db-wal", "state.db-shm"] {
                fixture::dump_windows_acl(&f.options.state_directory.join(name))?;
            }
            eprintln!("PRESERVED rejected SQLite fixture at {}", f.home.display());
            // Keep the exact rejected files until process exit, which releases
            // native handles without SQLite's normal last-connection unlink.
            std::mem::forget(store);
            std::mem::forget(lease);
            std::mem::forget(f);
            return Err(error.into());
        }
        assert!(observed?.is_some(), "native file readback absent {suffix}");
    }
    // Corrupt a maintained projection from outside its writer. Registered mail
    // must refuse rather than making an unread inbox disappear as a zero count.
    db.execute("DELETE FROM resume_heads", [])?;
    let mut s = store.snapshot(f.self_scope(&f.b))?;
    assert_eq!(
        s.message_count(query(Some(Actor::Agent(f.b.clone())), true))
            .err()
            .ok_or("missing head became zero")?
            .code,
        StoreErrorCode::ProjectionInconsistent
    );
    s.close()?;
    drop(db);
    store.close()?;
    Ok(())
}
