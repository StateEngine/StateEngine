use se_store::*;
use se_types::{DecisionId, EventId, ProjectId, Read};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
use std::time::Duration;
type Outcome<T> = Result<T, Box<dyn std::error::Error>>;
fn id() -> Outcome<DecisionId> {
    Ok(DecisionId::from_parts(
        1_700_000_000_000 + serial(),
        [95; 10],
    )?)
}
fn propose(
    f: &Fixture,
    s: &mut SqliteDirect,
    l: &Lease,
    d: &DecisionId,
    prior: Option<DecisionId>,
    text: &str,
) -> Outcome<EventId> {
    Ok(s.append(
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
            Some(request(&format!("fixture-proposal-{d}"))?),
            vec![EventBody::DecisionProposed {
                decision: d.clone(),
                key: "policy.files".into(),
                statement: InputText::Inline(text.into()),
                rationale: None,
                prior,
                kind: DecisionKind::Decision,
            }],
        )?,
        l,
    )?
    .primary_event)
}
fn append(
    f: &Fixture,
    s: &mut SqliteDirect,
    l: &Lease,
    body: EventBody<InputText>,
) -> Outcome<EventId> {
    Ok(s.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("fixture-transition-{}", serial()))?),
            vec![body],
        )?,
        l,
    )?
    .primary_event)
}
fn events(page: &se_types::Page<StoredEvent>) -> Vec<EventId> {
    page.items()
        .iter()
        .map(|e| e.header.event.clone())
        .collect()
}
fn foreign(f: &Fixture, s: &mut SqliteDirect, l: &Lease) -> Outcome<(ProjectId, DecisionId)> {
    let p = ProjectId::from_parts(1_700_000_000_000 + serial(), [96; 10])?;
    let d = id()?;
    s.append(
        f.batch(
            f.admission(Scope::Project(p.clone()), Actor::Human(f.owner.clone())),
            Some(request(&format!("fixture-project-{p}"))?),
            vec![
                EventBody::ProjectRegistered {
                    project: p.clone(),
                    name: "Other".into(),
                    roots: vec![],
                    owner: f.owner.clone(),
                    history_from: None,
                    expected: Expected::Absent,
                },
                EventBody::DecisionProposed {
                    decision: d.clone(),
                    key: "hidden.policy".into(),
                    statement: InputText::Inline("foreign private statement".into()),
                    rationale: None,
                    prior: None,
                    kind: DecisionKind::Decision,
                },
            ],
        )?,
        l,
    )?;
    Ok((p, d))
}
// Retained alias dictionary data exercises historical lookup names without
// claiming importer execution or conferring native/process authority.
fn alias(f: &Fixture, d: &DecisionId, p: &ProjectId) -> Outcome<DecisionId> {
    let old = DecisionId::from_legacy(format!("00000000-0000-4000-8000-{:012x}", serial()))?;
    let key = d.canonical_bytes()?.ok_or("canonical fixture decision")?;
    let mut scope = vec![1];
    scope.extend_from_slice(&p.canonical_bytes()?.ok_or("canonical project")?);
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    db.execute("INSERT INTO identities(storage_key,kind,wire_id,scope_key,encoding) VALUES(?,'decision',?,?,'legacy-shape')",rusqlite::params![key.as_slice(),old.as_str(),scope])?;
    Ok(old)
}

/// Protects: exact decision reads preserve immutable order, all own transitions and incoming supersede links, with no unrelated project history in either result.
#[test]
fn ordered_own_and_incoming_transitions() -> Check {
    let f = Fixture::new()?;
    let (mut s, l) = f.direct()?;
    let a = id()?;
    let b = id()?;
    let p = propose(&f, &mut s, &l, &a, None, "original statement")?;
    let r = append(
        &f,
        &mut s,
        &l,
        EventBody::DecisionRatified {
            decision: a.clone(),
            expected: revision(1)?,
            approval: p.clone(),
        },
    )?;
    let bp = propose(&f, &mut s, &l, &b, Some(a.clone()), "replacement")?;
    let br = append(
        &f,
        &mut s,
        &l,
        EventBody::DecisionRatified {
            decision: b.clone(),
            expected: revision(1)?,
            approval: bp.clone(),
        },
    )?;
    let Expected::Revision(two) = revision(2)? else {
        return Err("revision helper".into());
    };
    let superseded = append(
        &f,
        &mut s,
        &l,
        EventBody::DecisionSuperseded {
            prior: a.clone(),
            replacement: b.clone(),
            prior_expected: two,
            replacement_expected: two,
            approval: br.clone(),
        },
    )?;
    s.append(f.working("unrelated", Expected::Absent, "unrelated")?, &*l)?;
    let head = s.info()?.head;
    let mut snap = s.snapshot(f.scoped(Visibility::Owner))?;
    let old = present(snap.decision_transitions(a, budget(100, 65536, None)?)?)?;
    assert!(old.window().complete());
    assert_eq!(events(&old), vec![p, r, superseded.clone()]);
    let new = present(snap.decision_transitions(b, budget(100, 65536, None)?)?)?;
    assert!(new.window().complete());
    assert_eq!(events(&new), vec![bp, br, superseded]);
    snap.close()?;
    assert_eq!(s.info()?.head, head);
    s.close()?;
    Ok(())
}

/// Protects: transition cursors retain their original high-water across later writes, make progress without duplicates, and refuse another decision or principal.
#[test]
fn immutable_pagination_and_cursor_binding() -> Check {
    let f = Fixture::new()?;
    let (mut s, l) = f.direct()?;
    let d = id()?;
    let p = propose(&f, &mut s, &l, &d, None, "proposal")?;
    let r = append(
        &f,
        &mut s,
        &l,
        EventBody::DecisionRatified {
            decision: d.clone(),
            expected: revision(1)?,
            approval: p.clone(),
        },
    )?;
    let mut snap = s.snapshot(f.scoped(Visibility::Owner))?;
    let first = present(snap.decision_transitions(d.clone(), budget(1, 65536, None)?)?)?;
    assert_eq!(events(&first), vec![p.clone()]);
    assert!(!first.window().complete());
    let cursor = first
        .next()
        .ok_or("missing transition continuation")?
        .clone();
    snap.close()?;
    let last = append(
        &f,
        &mut s,
        &l,
        EventBody::DecisionRetracted {
            decision: d.clone(),
            expected: revision(2)?,
            reason: InputText::Inline("later withdrawal".into()),
        },
    )?;
    let mut fresh = s.snapshot(f.scoped(Visibility::Owner))?;
    let second =
        present(fresh.decision_transitions(d.clone(), budget(1, 65536, Some(cursor.clone()))?)?)?;
    assert_eq!(events(&second), vec![r.clone()]);
    assert!(second.window().complete());
    assert!(second.next().is_none());
    let complete = present(fresh.decision_transitions(d.clone(), budget(100, 65536, None)?)?)?;
    assert_eq!(events(&complete), vec![p, r, last]);
    assert_eq!(
        fresh
            .decision_transitions(id()?, budget(1, 65536, Some(cursor.clone()))?)
            .err()
            .ok_or("other decision accepted cursor")?
            .code,
        StoreErrorCode::CursorInvalid
    );
    fresh.close()?;
    let mut other = s.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        other
            .decision_transitions(d, budget(1, 65536, Some(cursor))?)
            .err()
            .ok_or("other principal accepted cursor")?
            .code,
        StoreErrorCode::CursorInvalid
    );
    other.close()?;
    s.close()?;
    Ok(())
}

/// Protects: finite byte and time limits refuse or state omissions honestly, and a timed-out read retires its progress hook before a subsequent healthy read.
#[test]
fn bounded_reads_and_progress_cleanup() -> Check {
    let f = Fixture::new()?;
    let (mut s, l) = f.direct()?;
    let d = id()?;
    let p = propose(&f, &mut s, &l, &d, None, &"large statement 🦀".repeat(100))?;
    append(
        &f,
        &mut s,
        &l,
        EventBody::DecisionRatified {
            decision: d.clone(),
            expected: revision(1)?,
            approval: p,
        },
    )?;
    let mut snap = s.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        snap.decision_transitions(d.clone(), budget(100, 1, None)?)
            .err()
            .ok_or("tiny budget silently truncated")?
            .code,
        StoreErrorCode::ReadBudgetTooSmall
    );
    let first = present(snap.decision_transitions(d.clone(), budget(1, 65536, None)?)?)?;
    let exact = u32::try_from(first.window().fields().ok_or("producer accounting")?.bytes)?;
    let bytes = present(snap.decision_transitions(d.clone(), budget(100, exact, None)?)?)?;
    assert_eq!(bytes.items().len(), 1);
    assert!(!bytes.window().complete());
    assert!(bytes.next().is_some());
    let mut time = budget(100, 65536, None)?;
    time.deadline = Duration::from_nanos(1);
    assert_eq!(
        snap.decision_transitions(d.clone(), time)
            .err()
            .ok_or("expired read reported complete")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    let healthy = present(snap.decision_transitions(d, budget(100, 65536, None)?)?)?;
    assert!(healthy.window().complete());
    assert_eq!(healthy.items().len(), 2);
    snap.close()?;
    s.close()?;
    Ok(())
}

/// Protects: unknown is absent, known foreign is a typed scope refusal for canonical and retained alias names, and per-event SelfOnly visibility cannot silently omit an owner transition.
#[test]
fn absence_scope_and_per_event_visibility() -> Check {
    let f = Fixture::new()?;
    let (mut s, l) = f.direct()?;
    let d = id()?;
    let p = propose(&f, &mut s, &l, &d, None, "Sable proposal")?;
    let (fp, fd) = foreign(&f, &mut s, &l)?;
    let old = alias(&f, &fd, &fp)?;
    let mut own = s.snapshot(f.self_scope(&f.a))?;
    assert!(matches!(
        own.decision_transitions(id()?, budget(100, 65536, None)?)?,
        Read::Absent { .. }
    ));
    for foreign_id in [fd, old] {
        assert_eq!(
            own.decision_transitions(foreign_id, budget(100, 65536, None)?)
                .err()
                .ok_or("foreign decision became absence")?
                .code,
            StoreErrorCode::ScopeMismatch
        );
    }
    assert_eq!(
        present(own.decision_transitions(d.clone(), budget(100, 65536, None)?)?)?
            .items()
            .len(),
        1
    );
    own.close()?;
    append(
        &f,
        &mut s,
        &l,
        EventBody::DecisionRatified {
            decision: d.clone(),
            expected: revision(1)?,
            approval: p,
        },
    )?;
    let mut private = s.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        private
            .decision_transitions(d.clone(), budget(100, 65536, None)?)
            .err()
            .ok_or("owner transition silently omitted")?
            .code,
        StoreErrorCode::ScopeMismatch
    );
    private.close()?;
    let mut shared = s.snapshot(f.scoped(Visibility::SharedProject(f.a.clone())))?;
    assert_eq!(
        present(shared.decision_transitions(d, budget(100, 65536, None)?)?)?
            .items()
            .len(),
        2
    );
    shared.close()?;
    s.close()?;
    Ok(())
}

/// Protects: a visible retained legacy lookup alias resolves the exact original canonical decision events without fabricating a different proposal identity.
#[test]
fn retained_alias_reads_visible_decision() -> Check {
    let f = Fixture::new()?;
    let (mut s, l) = f.direct()?;
    let d = id()?;
    let p = propose(&f, &mut s, &l, &d, None, "retained alias body")?;
    let old = alias(&f, &d, &f.project)?;
    let mut snap = s.snapshot(f.scoped(Visibility::Owner))?;
    let canonical = present(snap.decision_transitions(d, budget(100, 65536, None)?)?)?;
    assert_eq!(events(&canonical), vec![p.clone()]);
    let historical = present(snap.decision_transitions(old, budget(100, 65536, None)?)?)?;
    assert_eq!(events(&historical), vec![p]);
    snap.close()?;
    s.close()?;
    Ok(())
}

/// Protects: exact lookup does not decode unrelated damaged history, while corruption of the requested proposal remains an error rather than measured absence or a complete empty page.
#[test]
fn targeted_read_and_missing_proposal_are_distinct() -> Check {
    let f = Fixture::new()?;
    let (mut s, l) = f.direct()?;
    let d = id()?;
    let other = id()?;
    let p = propose(&f, &mut s, &l, &d, None, "requested body")?;
    let unrelated = propose(&f, &mut s, &l, &other, None, "unrelated body")?;
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    // Inject actual damaged bytes in this disposable database, bypassing only
    // its immutability triggers; production writes never take this path.
    db.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER payloads_no_update; DROP TRIGGER decision_data_no_delete;")?;
    let unrelated_key = unrelated.canonical_bytes()?.ok_or("canonical event")?;
    assert_eq!(db.execute("UPDATE payloads SET content=CAST('damaged without matching hash' AS BLOB) WHERE event_seq=(SELECT seq FROM events WHERE event_id=?)",[unrelated_key.as_slice()])?,1);
    let mut snap = s.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        events(&present(
            snap.decision_transitions(d.clone(), budget(100, 65536, None)?)?
        )?),
        vec![p]
    );
    assert!(
        snap.decision_transitions(other, budget(100, 65536, None)?)
            .is_err(),
        "damaged unrelated fixture was not active"
    );
    snap.close()?;
    let key = d.canonical_bytes()?.ok_or("canonical decision")?;
    assert_eq!(
        db.execute(
            "DELETE FROM decision_data WHERE decision_id=? AND state='proposed'",
            [key.as_slice()]
        )?,
        1
    );
    let mut snap = s.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        snap.decision_transitions(d, budget(100, 65536, None)?)
            .err()
            .ok_or("known missing proposal became absence")?
            .code,
        StoreErrorCode::ProjectionInconsistent
    );
    snap.close()?;
    s.close()?;
    Ok(())
}
